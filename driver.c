#include <ntddk.h>
#include <wdm.h>
#include "..\\UM\\alpc_common.h"
#include "definitions.h"
#include "physical_memory.h"
#include "spoof_call.h"
#include "memory.h"
#include "cleaner.h"

// Encryption functions are defined in alpc_common.h

// ALPC function declarations (manual to avoid ntifs.h conflicts)
NTSTATUS ZwAlpcCreatePort(_Out_ PHANDLE PortHandle,
                         _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                         _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes);

NTSTATUS ZwAlpcAcceptConnectPort(_Out_ PHANDLE PortHandle,
                                _In_ HANDLE ConnectionPortHandle,
                                _In_ ULONG Flags,
                                _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
                                _In_opt_ PVOID PortContext,
                                _In_ PPORT_MESSAGE ConnectionRequest,
                                _Inout_opt_ PVOID ConnectionMessageAttributes,
                                _In_ BOOLEAN AcceptConnection);

NTSTATUS ZwAlpcDisconnectPort(_In_ HANDLE PortHandle,
                             _In_ ULONG Flags);

NTSTATUS ZwAlpcSendWaitReceivePort(_In_ HANDLE PortHandle,
                                  _In_ ULONG Flags,
                                  _In_opt_ PPORT_MESSAGE SendMessage,
                                  _Inout_opt_ PVOID SendMessageAttributes,
                                  _Inout_opt_ PPORT_MESSAGE ReceiveMessage,
                                  _Inout_opt_ PSIZE_T BufferLength,
                                  _Inout_opt_ PVOID ReceiveMessageAttributes,
                                  _In_opt_ PLARGE_INTEGER Timeout);

NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(
    _In_ PEPROCESS Process
);

// Memory operations are now in physical_memory.h

#define DRIVER_TAG 'TPLT'

// Driver context structure
typedef struct _DRIVER_CONTEXT {
    HANDLE AlpcPortHandle;
    HANDLE AlpcClientHandle;
    BOOLEAN AlpcInitialized;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

PDRIVER_CONTEXT gDriverContext = NULL;

// Function declarations
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS AlpcInitialize();
VOID AlpcCleanup();
NTSTATUS AlpcMessageHandler(PALPC_MESSAGE Message);
VOID AlpcMessageHandlerThread(PVOID StartContext);
static VOID AlpcCloseHandle(PHANDLE Handle);

// Manual initialization for kdmapper
NTSTATUS ManualInitializeDriver();
VOID ManualCleanupDriver();

PVOID GetBaseFromProcess(HANDLE pid, const wchar_t* moduleName)
{
    PEPROCESS process = NULL;
    PVOID baseAddress = NULL;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) {
        return NULL;
    }

    // If no module name is provided or it's empty, return the main process base
    if (!moduleName || moduleName[0] == L'\0') {
        baseAddress = PsGetProcessSectionBaseAddress(process);
        ObfDereferenceObject(process);
        return baseAddress;
    }

    // Traverse the PEB using physical memory reads (stealthy, no KeStackAttachProcess)
    PPEB peb = PsGetProcessPeb(process);
    if (peb) {
        PEB pebCopy = {0};
        // Read PEB struct from target process
        if (PhysicalReadProcessMemory(pid, (ULONG64)peb, &pebCopy, sizeof(PEB))) {
            
            if (pebCopy.Ldr) {
                PEB_LDR_DATA ldrCopy = {0};
                // Read PEB_LDR_DATA
                if (PhysicalReadProcessMemory(pid, (ULONG64)pebCopy.Ldr, &ldrCopy, sizeof(PEB_LDR_DATA))) {
                    
                    PLIST_ENTRY listHead = &pebCopy.Ldr->InLoadOrderModuleList;
                    PLIST_ENTRY listEntry = ldrCopy.InLoadOrderModuleList.Flink;

                    UNICODE_STRING targetModule;
                    RtlInitUnicodeString(&targetModule, moduleName);

                    // Safety counter to prevent infinite loops in corrupted memory
                    ULONG maxIterations = 500;
                    
                    while (listEntry && listEntry != listHead && maxIterations-- > 0) {
                        LDR_DATA_TABLE_ENTRY entryCopy = {0};
                        
                        // Calculate address of LDR_DATA_TABLE_ENTRY
                        ULONG64 entryAddress = (ULONG64)CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                        
                        // Read the entry
                        if (!PhysicalReadProcessMemory(pid, entryAddress, &entryCopy, sizeof(LDR_DATA_TABLE_ENTRY))) {
                            break;
                        }

                        if (entryCopy.BaseDllName.Buffer != NULL && entryCopy.BaseDllName.Length > 0) {
                            // Read the actual string buffer
                            WCHAR nameBuffer[256] = {0};
                            ULONG bytesToRead = min(entryCopy.BaseDllName.Length, sizeof(nameBuffer) - sizeof(WCHAR));
                            
                            if (PhysicalReadProcessMemory(pid, (ULONG64)entryCopy.BaseDllName.Buffer, nameBuffer, bytesToRead)) {
                                UNICODE_STRING currentModule;
                                RtlInitUnicodeString(&currentModule, nameBuffer);
                                currentModule.Length = (USHORT)bytesToRead;
                                currentModule.MaximumLength = sizeof(nameBuffer);

                                if (RtlCompareUnicodeString(&currentModule, &targetModule, TRUE) == 0) {
                                    baseAddress = entryCopy.DllBase;
                                    break;
                                }
                            }
                        }
                        
                        listEntry = entryCopy.InLoadOrderLinks.Flink;
                    }
                }
            }
        }
    }

    ObfDereferenceObject(process);
    return baseAddress;
}

NTSTATUS ReadPhysicalMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size)
{
    return PhysicalReadProcessMemory(pid, address, buffer, size)
        ? STATUS_SUCCESS
        : STATUS_UNSUCCESSFUL;
}

NTSTATUS WritePhysicalMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size)
{
    return PhysicalWriteProcessMemory(pid, address, buffer, size)
        ? STATUS_SUCCESS
        : STATUS_UNSUCCESSFUL;
}

NTSTATUS ReadVirtualMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size)
{
    return ReadPhysicalMemory(pid, address, buffer, size);
}

NTSTATUS WriteVirtualMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size)
{
    return WritePhysicalMemory(pid, address, buffer, size);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
   NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    
    // Initialize spoof call functionality first
    if (!InitSpoofCall()) {
        KdPrint(("Failed to initialize spoof call functionality\n"));
        return STATUS_UNSUCCESSFUL;
    }
    
    // Allocate driver context
    gDriverContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(DRIVER_CONTEXT), DRIVER_TAG);
    if (!gDriverContext) {
        CleanupSpoofCall();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(gDriverContext, sizeof(DRIVER_CONTEXT));
    
    // Initialize ALPC
    status = AlpcInitialize();
    if (!NT_SUCCESS(status)) {
        CleanupSpoofCall();
        ExFreePoolWithTag(gDriverContext, DRIVER_TAG);
        gDriverContext = NULL;
        return status;
    }

    KdPrint(("TestTemplate Driver manually initialized successfully\n"));
    
    return STATUS_SUCCESS;
}

// Manual cleanup for kdmapper - call this before manual unmapping
VOID ManualCleanupDriver()
{
    if (gDriverContext) {
        if (gDriverContext->AlpcInitialized) {
            AlpcCleanup();
        }
        
        ExFreePoolWithTag(gDriverContext, DRIVER_TAG);
        gDriverContext = NULL;
    }
    
    // Cleanup spoof call functionality
    CleanupSpoofCall();
    
    KdPrint(("TestTemplate Driver manually cleaned up\n"));
}

NTSTATUS AlpcInitialize()
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES objectAttributes;
    ALPC_PORT_ATTRIBUTES portAttributes;
    
    RtlInitUnicodeString(&portName, ALPC_PORT_NAME);
    RtlZeroMemory(&portAttributes, sizeof(portAttributes));
    portAttributes.Flags = ALPC_PORFLG_SYSTEM_PROCESS;
    portAttributes.MaxMessageLength = sizeof(ALPC_TRANSPORT_MESSAGE);
    portAttributes.MemoryBandwidth = 0;
    portAttributes.MaxPoolUsage = ~(SIZE_T)0;
    portAttributes.MaxSectionSize = ~(SIZE_T)0;
    portAttributes.MaxViewSize = ~(SIZE_T)0;
    portAttributes.MaxTotalSectionSize = ~(SIZE_T)0;
    
    InitializeObjectAttributes(&objectAttributes,
                             &portName,
                             OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                             NULL,
                             NULL);
    
    // Create ALPC port
    gDriverContext->AlpcInitialized = TRUE;
    
    // If the port already exists (e.g. from a previous crash without proper cleanup),
    // ZwAlpcCreatePort will return STATUS_OBJECT_NAME_COLLISION (0xC0000035)
    status = ZwAlpcCreatePort(&gDriverContext->AlpcPortHandle,
                             &objectAttributes,
                             &portAttributes);
                             
    if (status == STATUS_OBJECT_NAME_COLLISION) {
        KdPrint(("ALPC port already exists, we should use a different name or restart the system\n"));
        // For testing purposes, let's append a random string or just fail gracefully
        gDriverContext->AlpcInitialized = FALSE;
        return status;
    }
    
    if (NT_SUCCESS(status)) {
        KdPrint(("ALPC port created successfully: %wZ\n", &portName));
        
        // Start message handling thread
        HANDLE threadHandle;
        status = PsCreateSystemThread(&threadHandle,
                                     THREAD_ALL_ACCESS,
                                     NULL,
                                     NULL,
                                     NULL,
                                     AlpcMessageHandlerThread,
                                     NULL);
        
        if (NT_SUCCESS(status)) {
            ZwClose(threadHandle);
        } else {
            gDriverContext->AlpcInitialized = FALSE;
            AlpcCloseHandle(&gDriverContext->AlpcPortHandle);
        }
    } else {
        gDriverContext->AlpcInitialized = FALSE;
    }
    
    return status;
}

VOID AlpcCleanup()
{
    gDriverContext->AlpcInitialized = FALSE;
    AlpcCloseHandle(&gDriverContext->AlpcClientHandle);
    AlpcCloseHandle(&gDriverContext->AlpcPortHandle);
}

static VOID AlpcCloseHandle(PHANDLE Handle)
{
    if (Handle != NULL && *Handle != NULL) {
        ZwAlpcDisconnectPort(*Handle, ALPC_CANCELFLG_TRY_CANCEL);
        ZwClose(*Handle);
        *Handle = NULL;
    }
}

VOID AlpcMessageHandlerThread(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);
    
    while (gDriverContext->AlpcInitialized) {
        ALPC_TRANSPORT_MESSAGE transport = {0};
        SIZE_T bufferLength = sizeof(transport);
        NTSTATUS status = ZwAlpcSendWaitReceivePort(gDriverContext->AlpcPortHandle,
                                                   0,
                                                   NULL,
                                                   NULL,
                                                   &transport.Header,
                                                   &bufferLength,
                                                   NULL,
                                                   NULL);

        if (!NT_SUCCESS(status)) {
            if (!gDriverContext->AlpcInitialized) {
                break;
            }

            LARGE_INTEGER delay;
            delay.QuadPart = -1000000; // 0.1 second
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            continue;
        }

        switch (AlpcGetPortMessageType(&transport.Header)) {
            case LPC_CONNECTION_REQUEST:
            {
                if (gDriverContext->AlpcClientHandle != NULL) {
                    HANDLE rejectedClientHandle = NULL;

                    status = ZwAlpcAcceptConnectPort(&rejectedClientHandle,
                                                   gDriverContext->AlpcPortHandle,
                                                   0,
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   &transport.Header,
                                                   NULL,
                                                   FALSE);

                    if (rejectedClientHandle != NULL) {
                        AlpcCloseHandle(&rejectedClientHandle);
                    }
                    break;
                }

                status = ZwAlpcAcceptConnectPort(&gDriverContext->AlpcClientHandle,
                                                   gDriverContext->AlpcPortHandle,
                                                   0,
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   &transport.Header,
                                                   NULL,
                                                   TRUE);
                    
                    if (NT_SUCCESS(status) && transport.Header.MessageId) {
                        // For connection messages, the data payload comes unencrypted
                        // but we send the response payload encrypted
                        ALPC_MESSAGE responsePayload = {0};
                        responsePayload.Type = ALPC_MESSAGE_RESPONSE;
                        responsePayload.Length = sizeof("Connected");
                        memcpy(responsePayload.Data, "Connected", responsePayload.Length);
                        
                        ALPC_ENCRYPT(&responsePayload);
                        
                        // In ALPC, the response to a connection request is sent back by
                        // providing the ConnectionMessage in ZwAlpcAcceptConnectPort itself
                        // or by sending a subsequent reply using the original message ID
                        ALPC_TRANSPORT_MESSAGE responseTransport = {0};
                        responseTransport.Header = transport.Header;
                        responseTransport.Header.u1.s1.DataLength = sizeof(responsePayload);
                        responseTransport.Header.u1.s1.TotalLength = sizeof(ALPC_TRANSPORT_MESSAGE);
                        responseTransport.Payload = responsePayload;
                        
                        // Acknowledge connection
                        status = ZwAlpcSendWaitReceivePort(gDriverContext->AlpcPortHandle,
                                                         0,
                                                         &responseTransport.Header,
                                                         NULL,
                                                         NULL,
                                                         NULL,
                                                         NULL,
                                                         NULL);
                    }
                    
                    // Reset status to success so we don't accidentally close the handle below
                    status = STATUS_SUCCESS;
                    break;
            }

            case LPC_REQUEST:
                if (gDriverContext->AlpcClientHandle == NULL) {
                    status = STATUS_PORT_DISCONNECTED;
                    break;
                }

                ALPC_DECRYPT(&transport.Payload);
                
                status = AlpcMessageHandler(&transport.Payload);
                if (!NT_SUCCESS(status)) {
                    break;
                }

                ALPC_ENCRYPT(&transport.Payload);
                if (AlpcPortMessageRequiresReply(&transport.Header)) {
                    status = ZwAlpcSendWaitReceivePort(gDriverContext->AlpcPortHandle,
                                                     ALPC_MSGFLG_RELEASE_MESSAGE,
                                                     &transport.Header,
                                                     NULL,
                                                     NULL,
                                                     NULL,
                                                     NULL,
                                                     NULL);
                }
                break;

            case LPC_PORT_CLOSED:
            case LPC_CLIENT_DIED:
                AlpcCloseHandle(&gDriverContext->AlpcClientHandle);
                status = STATUS_SUCCESS;
                break;

            default:
                status = STATUS_INVALID_PARAMETER;
                break;
        }

        if (!NT_SUCCESS(status) && gDriverContext->AlpcClientHandle != NULL) {
            AlpcCloseHandle(&gDriverContext->AlpcClientHandle);
        }
    }
    
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS AlpcMessageHandler(PALPC_MESSAGE Message)
{
    ALPC_MESSAGE response = {0};
    response.Type = ALPC_MESSAGE_RESPONSE;
    
    switch (Message->Type) {
        case ALPC_MESSAGE_CONNECT:
            response.Length = sizeof("Connected");
            memcpy(response.Data, "Connected", response.Length);
            break;
            
        case ALPC_MESSAGE_GET_BASE:
        {
            // Get base address from process
            const wchar_t* moduleName = (const wchar_t*)Message->Data;
            PVOID baseAddress = GetBaseFromProcess((HANDLE)Message->ProcessId, moduleName);
            
            if (baseAddress) {
                response.Length = sizeof(ULONG64);
                *(ULONG64*)response.Data = (ULONG64)baseAddress;
            } else {
                response.Length = sizeof("Failed to get base address");
                memcpy(response.Data, "Failed to get base address", response.Length);
            }
            break;
        }
            
        case ALPC_MESSAGE_READ_MEMORY:
        {
            // Read memory from process using physical memory operations for EAC bypass
            NTSTATUS readStatus = ReadPhysicalMemory((HANDLE)Message->ProcessId, (ULONG64)Message->Address, response.Data, (SIZE_T)min(Message->Size, sizeof(response.Data)));
            if (NT_SUCCESS(readStatus)) {
                response.Length = (ULONG)min(Message->Size, sizeof(response.Data));
            } else {
                response.Length = sizeof("Memory read failed");
                memcpy(response.Data, "Memory read failed", response.Length);
            }
            break;
        }
            
        case ALPC_MESSAGE_WRITE_MEMORY:
        {
            // Write memory to process using physical memory operations for EAC bypass
            NTSTATUS writeStatus = WritePhysicalMemory((HANDLE)Message->ProcessId, (ULONG64)Message->Address, Message->Data, (SIZE_T)min(Message->Length, Message->Size));
            if (NT_SUCCESS(writeStatus)) {
                response.Length = sizeof("Write successful");
                memcpy(response.Data, "Write successful", response.Length);
            } else {
                response.Length = sizeof("Memory write failed");
                memcpy(response.Data, "Memory write failed", response.Length);
            }
            break;
        }
            
        case ALPC_MESSAGE_DISCONNECT:
            response.Length = sizeof("Disconnected");
            memcpy(response.Data, "Disconnected", response.Length);
            break;
            
        default:
            response.Length = sizeof("Unknown message type");
            memcpy(response.Data, "Unknown message type", response.Length);
            break;
    }

    *Message = response;
    return STATUS_SUCCESS;
}

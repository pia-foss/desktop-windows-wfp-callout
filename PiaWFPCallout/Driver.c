// Copyright (c) 2020 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#include <ntddk.h>
#include <wdf.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <mstcpip.h>

#define htonl(l)                  \
   ((((l) & 0xFF000000) >> 24) | \
   (((l) & 0x00FF0000) >> 8)  |  \
   (((l) & 0x0000FF00) << 8)  |  \
   (((l) & 0x000000FF) << 24))

/**
 @macro="ntohl"

   Purpose:  Convert ULONG in Network Byte Order to Host Byte Order.                            <br>
                                                                                                <br>
   Notes:                                                                                       <br>
                                                                                                <br>
   MSDN_Ref:                                                                                    <br>
*/
#define ntohl(l)                   \
   ((((l) >> 24) & 0x000000FFL) | \
   (((l) >>  8) & 0x0000FF00L) |  \
   (((l) <<  8) & 0x00FF0000L) |  \
   (((l) << 24) & 0xFF000000L))


#define INITGUID
#include <guiddef.h>

DEVICE_OBJECT* gWdmDevice;
// Variable for the run-time callout identifier
UINT32 BindCalloutId = 0, ConnectCalloutId = 0;
WDFDEVICE wdfDevice;

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD DriverUnload;
EVT_WDF_DRIVER_DEVICE_ADD PiaWFPEvtDeviceAdd;

DEFINE_GUID(
    PIA_WFP_CALLOUT_BIND_V4,
    0xb16b0a6e,
    0x2b2a,
    0x41a3,
    0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8
);

DEFINE_GUID(
    PIA_WFP_CALLOUT_CONNECT_V4,
    0xb80ca14a,
    0xa807,
    0x4ef2,
    0x87, 0x2d, 0x4b, 0x1a, 0x51, 0x82, 0x54, 0x2
);

NTSTATUS NTAPI
NotifyFn(
    IN FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
    IN const GUID* filterKey,
    IN const FWPS_FILTER1* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

// Build an IPv4 address in host byte order
UINT32 ipv4(UINT8 b0, UINT8 b1, UINT8 b2, UINT8 b3)
{
    UINT32 addr = b0;
    addr <<= 8;
    addr |= b1;
    addr <<= 8;
    addr |= b2;
    addr <<= 8;
    addr |= b3;
    return addr;
}

// Check if an IPv4 address in host byte order is in a subnet identified by
// address and subnet mask
BOOL inSubnet(UINT32 addr, UINT8 b0, UINT8 b1, UINT8 b2, UINT8 b3, UINT8 mb0, UINT8 mb1, UINT8 mb2, UINT8 mb3)
{
    UINT32 net = ipv4(b0, b1, b2, b3);
    UINT32 mask = ipv4(mb0, mb1, mb2, mb3);
    return (addr & mask) == net;
}

BOOL isLocal(UINT32 addr)
{
    return inSubnet(addr, 127, 0, 0, 0, 255, 0, 0, 0) ||
       inSubnet(addr, 192, 168, 0, 0, 255, 255, 0, 0) ||
       inSubnet(addr, 172, 16, 0, 0, 255, 240, 0, 0) ||
       inSubnet(addr, 10, 0, 0, 0, 255, 0, 0, 0) ||
       inSubnet(addr, 224, 0, 0, 0, 240, 0, 0, 0) ||
       inSubnet(addr, 169, 254, 0, 0, 255, 255, 0, 0) ||
       addr == 0xFFFFFFFF;
}

VOID
checkBindRedirect(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _Inout_opt_ void* layerData,
    _In_opt_  const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    NT_ASSERT(inFixedValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V4);
    NT_ASSERT(filter);
    NT_ASSERT(filter->providerContext);
    NT_ASSERT(filter->providerContext->dataBuffer);
    NT_ASSERT(filter->providerContext->dataBuffer->data);

    NTSTATUS status;

    // Sanity check
    if(!layerData || !classifyContext || inFixedValues->layerId != FWPS_LAYER_ALE_BIND_REDIRECT_V4)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(b): Not rebinding connection - failed sanity check\n"));
        return;
    }

    IN_ADDR originalSourceIp = { 0 };
    UINT32 originalSource = inFixedValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    originalSourceIp.S_un.S_addr = htonl(originalSource);
    char originalSourceIpStr[32];
    RtlIpv4AddressToStringA(&originalSourceIp, originalSourceIpStr);

    // Can't rebind if the right is missing (somebody already rebound it)
    if(!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(b): Not rebinding connection from %s - unable to write\n",
                   originalSourceIpStr));
        return;
    }

    // Only do this for new sockets, "reauthorize" indicates that the classify
    // is applying due to a filter change
    if(inFixedValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_FLAGS].value.uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(b): Not rebinding connection from %s - is reauthorize\n",
                   originalSourceIpStr));
        return;
    }

    // Don't bind TCP sockets, this breaks connections to LAN/localhost - handle
    // those in connect instead
    // (Binding non-TCP sockets still breaks LAN/localhost, but WFP doesn't
    // allow us to rebind those in connect, it's ignored.)
    // 6 == TCP - RFC1700
    if(inFixedValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_PROTOCOL].value.uint8 == 6)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(b): Not rebinding connection from %s with protocol %d\n",
                   originalSourceIpStr, (UINT32)(inFixedValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_PROTOCOL].value.uint8)));
        return;
    }

    IN_ADDR newSourceIp = { 0 };
    newSourceIp.S_un.S_addr = htonl(*(UINT32*)(filter->providerContext->dataBuffer->data));

    // Don't rebind local/LAN/etc.
    if(isLocal(originalSource))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(b): Not rebinding loopback/local: %s\n", originalSourceIpStr));
        return;
    }

    UINT64 classifyHandle = 0;
    FWPS_BIND_REQUEST *bindRequest;

    status = FwpsAcquireClassifyHandle((void *)classifyContext, 0, &classifyHandle);
    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(b): Failed to acquire classify handle: %s - %X\n", originalSourceIpStr, status));
        return;
    }

    status = FwpsAcquireWritableLayerDataPointer(classifyHandle, filter->filterId, 0, &bindRequest, classifyOut);
    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(b): Failed to acquire writable data: %s - %X\n", originalSourceIpStr, status));
        FwpsReleaseClassifyHandle(classifyHandle);
        return;
    }

    char newSourceIpStr[32];
    RtlIpv4AddressToStringA(&newSourceIp, newSourceIpStr);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(b): rebind %s to %s\n",
               originalSourceIpStr, newSourceIpStr));

    // Rewrite the ip address to the one provided - then via the 'strong host model' packets from this socket will get routed out the interface with this ip
    INETADDR_SET_ADDRESS((PSOCKADDR) &(bindRequest->localAddressAndPort), (BYTE*)&newSourceIp);

    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    FwpsApplyModifiedLayerData(classifyHandle, &bindRequest, 0);
    FwpsReleaseClassifyHandle(classifyHandle);
}

VOID
checkConnectRedirect(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _Inout_opt_ void* layerData,
    _In_opt_  const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    NT_ASSERT(inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4);
    NT_ASSERT(filter);
    NT_ASSERT(filter->providerContext);
    NT_ASSERT(filter->providerContext->dataBuffer);
    NT_ASSERT(filter->providerContext->dataBuffer->data);

    NTSTATUS status;

    // Sanity check
    if(!layerData || !classifyContext || inFixedValues->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V4)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): Not rebinding connection - failed sanity check\n"));
        return;
    }

    IN_ADDR originalRemoteIp = { 0 };
    UINT32 origRemote = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    originalRemoteIp.S_un.S_addr = htonl(origRemote);
    char originalRemoteIpStr[32];
    RtlIpv4AddressToStringA(&originalRemoteIp, originalRemoteIpStr);

    // Can't rebind if the right is missing (somebody already rebound it)
    if(!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): Not rebinding connection to %s - unable to write\n",
                   originalRemoteIpStr));
        return;
    }

    // Only do this for new sockets, "reauthorize" indicates that the classify
    // is applying due to a filter change
    if(inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_FLAGS].value.uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): Not rebinding connection to %s - is reauthorize\n",
                   originalRemoteIpStr));
        return;
    }

    // Only bind TCP connections, this does not affect non-TCP connections in WFP.
    // MS documentation is conflicting, but this document indicates that it is
    // supposed to work in the CONNECT_REDIRECT layer for TCP (and it does seem
    // to work in practice):
    // https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    // 6 == TCP - RFC1700
    if(inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8 != 6)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): Not rebinding connection to %s with protocol %d\n",
                   originalRemoteIpStr, (UINT32)(inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8)));
        return;
    }

    // Do not redirect loopback, LAN, broadcast, or multicast
    if(inSubnet(origRemote, 127, 0, 0, 0, 255, 0, 0, 0) ||
       inSubnet(origRemote, 192, 168, 0, 0, 255, 255, 0, 0) ||
       inSubnet(origRemote, 172, 16, 0, 0, 255, 240, 0, 0) ||
       inSubnet(origRemote, 10, 0, 0, 0, 255, 0, 0, 0) ||
       inSubnet(origRemote, 224, 0, 0, 0, 240, 0, 0, 0) ||
       inSubnet(origRemote, 169, 254, 0, 0, 255, 255, 0, 0) ||
       origRemote == 0xFFFFFFFF)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): Not rebinding loopback/local: %s\n", originalRemoteIpStr));
        return;
    }

    UINT64 classifyHandle = 0;
    FWPS_CONNECT_REQUEST *connectRequest;

    status = FwpsAcquireClassifyHandle((void *)classifyContext, 0, &classifyHandle);
    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): Failed to acquire classify handle: %s - %X\n", originalRemoteIpStr, status));
        return;
    }

    status = FwpsAcquireWritableLayerDataPointer(classifyHandle, filter->filterId, 0, &connectRequest, classifyOut);
    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): Failed to acquire writable data: %s - %X\n", originalRemoteIpStr, status));
        FwpsReleaseClassifyHandle(classifyHandle);
        return;
    }

    IN_ADDR bindIp = { 0 };
    bindIp.S_un.S_addr = htonl(*(UINT32*)(filter->providerContext->dataBuffer->data));
    char bindIpStr[32];
    RtlIpv4AddressToStringA(&bindIp, bindIpStr);

    // Rebind the local IP address.
    char localIpStr[32];
    RtlIpv4AddressToStringA(&(((SOCKADDR_IN*)(&connectRequest->localAddressAndPort))->sin_addr), localIpStr);
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): rebind source from %s to %s -> %s\n",
               localIpStr, bindIpStr, originalRemoteIpStr));
    INETADDR_SET_ADDRESS((PSOCKADDR)&(connectRequest->localAddressAndPort),
                         (BYTE*)&bindIp);

    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    FwpsApplyModifiedLayerData(classifyHandle, &connectRequest, 0);
    FwpsReleaseClassifyHandle(classifyHandle);
}

VOID NTAPI
ClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_  const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(flowContext);

    NT_ASSERT(inFixedValues);

    if(!filter || !filter->providerContext ||
       filter->providerContext->type != FWPM_GENERAL_CONTEXT ||
       !filter->providerContext->dataBuffer)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: no provider context\n"));
        return;
    }

    if(filter->providerContext->dataBuffer->size != 4)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: expected context of 4 bytes, got %d\n",
                  filter->providerContext->dataBuffer->size));
        return;
    }

    switch(inFixedValues->layerId)
    {
        case FWPS_LAYER_ALE_BIND_REDIRECT_V4:
            checkBindRedirect(inFixedValues, layerData, classifyContext, filter, classifyOut);
            break;
        case FWPS_LAYER_ALE_CONNECT_REDIRECT_V4:
            checkConnectRedirect(inFixedValues, layerData, classifyContext, filter, classifyOut);
            break;
        default:
            break;
    }
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
DriverUnload(
    _In_ WDFDRIVER driverObject
)
{
    UNREFERENCED_PARAMETER(driverObject);

    // Unregister the callout
    NTSTATUS bindStatus = FwpsCalloutUnregisterById0(BindCalloutId);
    NTSTATUS connectStatus = FwpsCalloutUnregisterById0(ConnectCalloutId);

    if(NT_SUCCESS(bindStatus))
        BindCalloutId = 0;
    else
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: could not unregister bind callout, status code: %d\n", bindStatus));

    if(NT_SUCCESS(connectStatus))
        ConnectCalloutId = 0;
    else
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: could not unregister connect callout, status code: %d\n", connectStatus));

    // Delete the framework device object
    if(NT_SUCCESS(bindStatus) && NT_SUCCESS(connectStatus))
        WdfObjectDelete(wdfDevice);
}

NTSTATUS
InitDriverObjects(
    _Inout_ DRIVER_OBJECT* driverObject,
    _In_ const UNICODE_STRING* registryPath,
    _Out_ WDFDRIVER* pDriver,
    _Out_ WDFDEVICE* pDevice
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    PWDFDEVICE_INIT pInit = NULL;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;

    // Associate the unload function
    config.EvtDriverUnload = DriverUnload;

    status = WdfDriverCreate(
        driverObject,
        registryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        pDriver
    );

    if(!NT_SUCCESS(status))
    {
        return status;
    }

    pInit = WdfControlDeviceInitAllocate(*pDriver, &SDDL_DEVOBJ_KERNEL_ONLY);

    if(!pInit)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(pInit, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(pInit, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetCharacteristics(pInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

    status = WdfDeviceCreate(&pInit, WDF_NO_OBJECT_ATTRIBUTES, pDevice);
    if(!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(pInit);
        return status;
    }

    WdfControlFinishInitializing(*pDevice);

    return status;
}

NTSTATUS RegisterRedirectionCallout(_Inout_ void* deviceObject)
{
    // Explicilty use win7 friendly structures (see: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/fwpsk/ns-fwpsk-fwps_callout1_)
    FWPS_CALLOUT1 sCallout = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    sCallout.calloutKey = PIA_WFP_CALLOUT_BIND_V4;
    sCallout.classifyFn = ClassifyFn;
    sCallout.notifyFn = NotifyFn;

    status = FwpsCalloutRegister1(deviceObject, &sCallout, &BindCalloutId);

    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: failed to register bind callout - %X\n", status));
        return status;
    }

    sCallout.calloutKey = PIA_WFP_CALLOUT_CONNECT_V4;
    status = FwpsCalloutRegister1(deviceObject, &sCallout, &ConnectCalloutId);
    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: failed to register connect callout - %X\n", status));
        return status;
    }

    return status;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     driverObject,
    _In_ PUNICODE_STRING    registryPath
)
{
    // NTSTATUS variable to record success or failure
    NTSTATUS status = STATUS_SUCCESS;

    WDFDRIVER driver = { 0 };

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: DriverEntry\n"));

    status = InitDriverObjects(driverObject, registryPath, &driver, &wdfDevice);

    if(!NT_SUCCESS(status)) return status;

    gWdmDevice = WdfDeviceWdmGetDeviceObject(wdfDevice);

    status = RegisterRedirectionCallout(gWdmDevice);

    return status;
}

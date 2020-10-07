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

#include "DnsFlows.h"
#include <ntddk.h>
#include <wdf.h>
#include <fwpmk.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <mstcpip.h>

#pragma pack(push, 1)

#define DEBUG_PRINT(...)  \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
              "PIA_CALLOUT: " __VA_ARGS__))

typedef struct _IPV4_HEADER
{
    UINT8  VersionAndHeaderLength;
    UINT8  TypeOfService;
    UINT16 TotalLength;
    UINT16 Identification;
    UINT16 FlagsAndFragmentOffset;
    UINT8  TimeToLive;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SourceAddress;
    UINT32 DestinationAddress;
} IPV4_HEADER, * PIPV4_HEADER;

// Generic "transport port" header, this part is the same for both TCP and UDP.
typedef struct _TRANSPORT_PORT_HEADER
{
    UINT16 SourcePort;
    UINT16 DestinationPort;
} TRANSPORT_PORT_HEADER;

typedef struct _UDP_HEADER
{
    UINT16 SourcePort;
    UINT16 DestinationPort;
    UINT16 Length;
    UINT16 Checksum;
} UDP_HEADER;

#pragma pack(pop)

#define htonl(l)                  \
   ((((l) & 0xFF000000) >> 24) | \
   (((l) & 0x00FF0000) >> 8)  |  \
   (((l) & 0x0000FF00) << 8)  |  \
   (((l) & 0x000000FF) << 24))
#define ntohl(l) htonl(l)

#define ntohs(s) ((((s) & 0x00FF) << 8) | (((s) & 0xFF00) >> 8))
#define htons(s) ntohs(s)

#define INITGUID
#include <guiddef.h>

// Variable for the run-time callout identifier
UINT32 BindCalloutId = 0, ConnectCalloutId = 0, FlowEstablishedCalloutId = 0,
       ConnectAuthCalloutId = 0, IpInboundCalloutId = 0, IpOutboundCalloutId = 0;
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

DEFINE_GUID(
    PIA_WFP_CALLOUT_FLOW_ESTABLISHED_V4,
    0x18ebe4a1,
    0xa7b4,
    0x4b76,
    0x9f, 0x39, 0x28, 0x57, 0x1e, 0xaa, 0x6b, 0x6
);

DEFINE_GUID(
    PIA_WFP_CALLOUT_CONNECT_AUTH_V4,
    0xf6e93b65,
    0x5cd0,
    0x4b0d,
    0xa9, 0x4c, 0x13, 0xba, 0xfd, 0x92, 0xf4, 0x1c
);

DEFINE_GUID(
    PIA_WFP_CALLOUT_IPPACKET_INBOUND_V4,
    0x6a564cd3,
    0xd14e,
    0x43dc,
    0x98, 0xde, 0xa4, 0x18, 0x14, 0x4d, 0x5d, 0xd2
);

DEFINE_GUID(
    PIA_WFP_CALLOUT_IPPACKET_OUTBOUND_V4,
    0xb06c0a5f,
    0x2b58,
    0x6753,
    0x85, 0x29, 0xad, 0x8f, 0x1c, 0x51, 0x5f, 0xf5
);

HANDLE g_injectionHandle = NULL;
NDIS_HANDLE g_netBufferListPool = NULL;

typedef struct ContextData_T {
    UINT32 bindIp;
    // The address (host byte order) that DNS requests will be rewritten to.
    // If this is 0, DNS requests are passed without being rewritten.
    UINT32 rewriteDnsServer;
    // The source IP to use when rewriting DNS requests.
    UINT32 dnsSourceIp;
} ContextData;

void UpdateIpv4HeaderChecksum(PIPV4_HEADER IpHeader, UINT32 IpHeaderSize);

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

BOOL injectedBySelf(const NET_BUFFER_LIST *pNbl)
{
    FWPS_PACKET_INJECTION_STATE injectState;
    injectState = FwpsQueryPacketInjectionState(g_injectionHandle, pNbl, NULL);
    return injectState == FWPS_PACKET_INJECTED_BY_SELF ||
        injectState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF;
}

ContextData *getContextData(const FWPS_FILTER1 *filter, char dbgDirChar)
{
    UNREFERENCED_PARAMETER(dbgDirChar);

    UINT32 contextSize = 0;
    if(filter && filter->providerContext && filter->providerContext->dataBuffer)
        contextSize = filter->providerContext->dataBuffer->size;
    if(contextSize != sizeof(ContextData))
    {
        DEBUG_PRINT("(%c): expected context of %d bytes, got %d\n",
                    dbgDirChar, sizeof(ContextData), contextSize);
        return NULL;
    }
    return (ContextData*)(filter->providerContext->dataBuffer->data);
}

VOID NTAPI
permitInjectedConnect(
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
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    UINT32 localIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
    UINT32 remoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    UNREFERENCED_PARAMETER(remotePort);  // used only for debug tracing

    // Can't rebind if the right is missing (somebody already rebound it)
    if(!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
    {
        DEBUG_PRINT("(p) cannot check DNS flow %08X:%d -> %08X:%d, unable to write",
                    localIp, localPort, remoteIp, remotePort);
        return;
    }

    // If the packet was injected by us, explicitly permit it, overriding PIA's
    // normal filters.
    // This allows us to redirect bypass app DNS to the user's existing DNS
    // servers, which are normally blocked by leak protection.
    if(injectedBySelf(layerData))
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        DEBUG_PRINT("(p) permit injected DNS flow %08X:%d -> %08X:%d",
                    localIp, localPort, remoteIp, remotePort);
    }
    else
    {
        // If the packet wasn't injected by us, but is a flow that we expect to
        // rewrite, permit that too.  This allows (for example) VPN-only apps to try
        // to send to the default DNS when the default behavior is set to bypass,
        // and then we'll rewrite those packets to the VPN-only DNS.
        DnsFlow permitFlow = {0};
        permitFlow.actualLocalIp = localIp;
        permitFlow.actualRemoteIp = remoteIp;
        permitFlow.localPort = localPort;
        if(DnsFlow_Permit(&permitFlow))
        {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            DEBUG_PRINT("(p) permit DNS flow to be rewritten %08X:%d -> %08X:%d",
                        localIp, localPort, remoteIp, remotePort);
        }
        else
        {
            // Otherwise, defer to our normal filters in this layer.
            classifyOut->actionType = FWP_ACTION_BLOCK;
            DEBUG_PRINT("(p) block non-injected DNS flow %08X:%d -> %08X:%d",
                        localIp, localPort, remoteIp, remotePort);
        }
    }
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

VOID NTAPI
checkBindRedirect(
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

    NT_ASSERT(inFixedValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V4);

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

    ContextData* contextData = getContextData(filter, 'b');
    if(!contextData)
        return;

    IN_ADDR newSourceIp = { 0 };
    newSourceIp.S_un.S_addr = htonl(contextData->bindIp);

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

VOID NTAPI
checkConnectRedirect(
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

    NT_ASSERT(inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4);

    NTSTATUS status;

    // Sanity check
    if(!layerData || !classifyContext || inFixedValues->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V4)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): Not rebinding connection - failed sanity check\n"));
        return;
    }

    IN_ADDR originalRemoteIp = { 0 };
    UINT32 origRemoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT8 protocolNum = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
    originalRemoteIp.S_un.S_addr = htonl(origRemoteIp);
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

    ContextData* contextData = getContextData(filter, 'c');
    if(!contextData)
        return;

    // Only bind TCP connections, this does not affect non-TCP connections in WFP.
    // MS documentation is conflicting, but this document indicates that it is
    // supposed to work in the CONNECT_REDIRECT layer for TCP (and it does seem
    // to work in practice):
    // https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    // 6 == TCP - RFC1700
    if(protocolNum != IPPROTO_TCP)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(c): Not rebinding connection to %s with protocol %d\n",
                   originalRemoteIpStr, (UINT32)(inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8)));
        return;
    }

    // Do not redirect loopback, LAN, broadcast, or multicast
    if(inSubnet(origRemoteIp, 127, 0, 0, 0, 255, 0, 0, 0) ||
       inSubnet(origRemoteIp, 192, 168, 0, 0, 255, 255, 0, 0) ||
       inSubnet(origRemoteIp, 172, 16, 0, 0, 255, 240, 0, 0) ||
       inSubnet(origRemoteIp, 10, 0, 0, 0, 255, 0, 0, 0) ||
       inSubnet(origRemoteIp, 224, 0, 0, 0, 240, 0, 0, 0) ||
       inSubnet(origRemoteIp, 169, 254, 0, 0, 255, 255, 0, 0) ||
       origRemoteIp == 0xFFFFFFFF)
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
    bindIp.S_un.S_addr = htonl(contextData->bindIp);
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
FlowEstablished(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_  const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);

    NT_ASSERT(inFixedValues->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4);

    classifyOut->actionType = FWP_ACTION_CONTINUE;

    // Sanity check
    if(inFixedValues->layerId != FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(e): Not inspecting flow - failed sanity check\n"));
        return;
    }

    IN_ADDR originalRemoteIp = { 0 };
    UINT32 origRemoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT8 protocolNum = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;
    originalRemoteIp.S_un.S_addr = htonl(origRemoteIp);
    char originalRemoteIpStr[32];
    RtlIpv4AddressToStringA(&originalRemoteIp, originalRemoteIpStr);

    // Only do this for new sockets, "reauthorize" indicates that the classify
    // is applying due to a filter change
    if(inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_FLAGS].value.uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT(e): Not inspecting flow to %s - is reauthorize\n",
                   originalRemoteIpStr));
        return;
    }

    // If the packet was injected by us, do nothing
    if(injectedBySelf(layerData))
        return;

    ContextData* contextData = getContextData(filter, 'e');
    if(!contextData)
        return;
    UINT32 origLocalIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;
    UINT16 sourcePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;

    // If we already have a flow context, do nothing - we've already observed
    // this flow and created a DNS flow.
    //
    // This happens when checking the default behavior after having matched an
    // app rule.  We still want to apply DNS rewriting for default apps too -
    // when using split tunnel DNS, some apps may not query all DNS servers
    // right away, we rewrite other servers rather than blocking to ensure that
    // responses are received quickly.  This also serves as DNS leak protection.
    if(flowContext)
    {
        DEBUG_PRINT("(e): already observed DNS flow: %08X:%d -> %08X:%d, ignore default rule to use %08X\n",
                    origLocalIp, sourcePort, origRemoteIp, remotePort,
                    contextData->rewriteDnsServer);
        return;
    }

    // If this is a UDP DNS connection, and DNS rewriting is enabled in context,
    // keep track of it so we can rewrite DNS packets later in the IP packet
    // layers.
    if(contextData->rewriteDnsServer && protocolNum == IPPROTO_UDP &&
       remotePort == 53)
    {
        DEBUG_PRINT("(e): found a DNS flow: context rewrite DNS %08X, proto %d, source port %d, remote port %d\n",
                    contextData->rewriteDnsServer, protocolNum, sourcePort, remotePort);
        DnsFlow newDnsFlow = {0};
        newDnsFlow.actualLocalIp = origLocalIp;
        newDnsFlow.actualRemoteIp = origRemoteIp;
        newDnsFlow.intendedLocalIp = contextData->dnsSourceIp;
        newDnsFlow.intendedRemoteIp = contextData->rewriteDnsServer;
        newDnsFlow.localPort = sourcePort;
        UINT64 flowToken = DnsFlow_Add(&newDnsFlow);

        if(!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE))
        {
            DEBUG_PRINT("(e): failed to set flow context on DNS flow: flow handle not given\n");
        }
        else if(flowToken)  // If flowToken is 0, DnsFlow_Add() traced the error
        {
            // Set a nonzero flow context to be notified when the flow is
            // destroyed.  This is necessary in case the port is reused by a
            // different application, which has been observed to happen quickly
            // in some cases (shorter than the 60-second ALE layer timeout if
            // the port is explicitly closed).
            //
            // This is the only way to be notified when a flow is destroyed.
            // Many examples allocate memory for use as the flow context, but in
            // our case we can just store the flow token to delete the flow.
            NTSTATUS flowCtxStatus = FwpsFlowAssociateContext0(inMetaValues->flowHandle,
                                                               FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4,
                                                               FlowEstablishedCalloutId,
                                                               flowToken);
            if(NT_SUCCESS(flowCtxStatus))
            {
                DEBUG_PRINT("(e): set flow context on DNS flow to %X\n", flowToken);
            }
            else
            {
                DEBUG_PRINT("(e): failed to set flow context on DNS flow: %08X\n", flowCtxStatus);
            }
        }
    }
    else
    {
        DEBUG_PRINT("(e): not a DNS flow: context rewrite DNS %08X, proto %d, remote port %d\n",
                    contextData->rewriteDnsServer, protocolNum, sourcePort, remotePort);
    }
}

void NTAPI
FlowDeleted(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);

    DnsFlow_Delete(flowContext);
}

void NTAPI DriverIpPacketInboundClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI DriverIpPacketOutboundClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

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
    NTSTATUS flowEstablishedStatus = FwpsCalloutUnregisterById0(FlowEstablishedCalloutId);
    NTSTATUS connectAuthStatus = FwpsCalloutUnregisterById0(ConnectAuthCalloutId);
    NTSTATUS ipInboundStatus = FwpsCalloutUnregisterById0(IpInboundCalloutId);
    NTSTATUS ipOutboundStatus = FwpsCalloutUnregisterById0(IpOutboundCalloutId);

    if(NT_SUCCESS(bindStatus))
        BindCalloutId = 0;
    else
        DEBUG_PRINT("could not unregister bind callout, status code: %08X\n", bindStatus);

    if(NT_SUCCESS(connectStatus))
        ConnectCalloutId = 0;
    else
        DEBUG_PRINT("could not unregister connect callout, status code: %08X\n", connectStatus);

    if(NT_SUCCESS(flowEstablishedStatus))
        FlowEstablishedCalloutId = 0;
    else
        DEBUG_PRINT("could not unregister flow established callout, status code: %08X\n", flowEstablishedStatus);

    if(NT_SUCCESS(connectAuthStatus))
        ConnectAuthCalloutId = 0;
    else
        DEBUG_PRINT("could not unregister connect_auth callout, status code: %08X\n", connectAuthStatus);

    if(NT_SUCCESS(ipInboundStatus))
        IpInboundCalloutId = 0;
    else
        DEBUG_PRINT("could not unregister ipInbound callout, status code: %08X\n", ipInboundStatus);

    if(NT_SUCCESS(ipOutboundStatus))
        IpOutboundCalloutId = 0;
    else
        DEBUG_PRINT("could not unregister ipOutbound callout, status code: %08X\n", ipOutboundStatus);

    // Delete the framework device object
    if(!BindCalloutId && !ConnectCalloutId && !FlowEstablishedCalloutId &&
       !ConnectAuthCalloutId && !IpInboundCalloutId && !IpOutboundCalloutId)
    {
        WdfObjectDelete(wdfDevice);
    }

    DnsFlow_Teardown();

    // Destroy the injection handle
    NTSTATUS injectionDestroyStatus = FwpsInjectionHandleDestroy(g_injectionHandle);
    if(NT_SUCCESS(injectionDestroyStatus))
        g_injectionHandle = NULL;
    else
        DEBUG_PRINT("could not destroy injection handle, status code: %08X\n", injectionDestroyStatus);

    // Destroy the NBL pool
    NdisFreeNetBufferListPool(g_netBufferListPool);
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
    sCallout.classifyFn = checkBindRedirect;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister1(deviceObject, &sCallout, &BindCalloutId);

    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: failed to register bind callout - %X\n", status));
        return status;
    }

    sCallout.calloutKey = PIA_WFP_CALLOUT_CONNECT_V4;
    sCallout.classifyFn = checkConnectRedirect;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = NULL;
    status = FwpsCalloutRegister1(deviceObject, &sCallout, &ConnectCalloutId);
    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: failed to register connect callout - %X\n", status));
        return status;
    }

    sCallout.calloutKey = PIA_WFP_CALLOUT_FLOW_ESTABLISHED_V4;
    sCallout.classifyFn = FlowEstablished;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleted;
    status = FwpsCalloutRegister1(deviceObject, &sCallout, &FlowEstablishedCalloutId);
    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: failed to register flow established callout - %X\n", status));
        return status;
    }

    sCallout.calloutKey = PIA_WFP_CALLOUT_CONNECT_AUTH_V4;
    sCallout.classifyFn = permitInjectedConnect;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = NULL;
    status = FwpsCalloutRegister1(deviceObject, &sCallout, &ConnectAuthCalloutId);
    if(!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: failed to register connect_auth callout - %X\n", status));
        return status;
    }

    sCallout.calloutKey = PIA_WFP_CALLOUT_IPPACKET_INBOUND_V4;
    sCallout.classifyFn = DriverIpPacketInboundClassify;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = NULL;
    status = FwpsCalloutRegister1(deviceObject, &sCallout, &IpInboundCalloutId);
    if (!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: failed to register ip inbound callout - %X\n", status));
        return status;
    }

    sCallout.calloutKey = PIA_WFP_CALLOUT_IPPACKET_OUTBOUND_V4;
    sCallout.classifyFn = DriverIpPacketOutboundClassify;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = NULL;
    status = FwpsCalloutRegister1(deviceObject, &sCallout, &IpOutboundCalloutId);
    if (!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: failed to register ip outbound callout - %X\n", status));
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

    if(!NT_SUCCESS(status))
    {
        DriverUnload(NULL);
        return status;
    }

    DnsFlow_Init();

    DEVICE_OBJECT* pWdmDevice = WdfDeviceWdmGetDeviceObject(wdfDevice);

    status = RegisterRedirectionCallout(pWdmDevice);

    status = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &g_injectionHandle);
    if(!g_injectionHandle || !NT_SUCCESS(status))
    {
        DEBUG_PRINT("Can't create injection handle - %08X\n", status);
        DriverUnload(NULL);
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    NET_BUFFER_LIST_POOL_PARAMETERS poolParams = { 0 };
    poolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    poolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    poolParams.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    poolParams.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    // With fAllocateNetBuffer = TRUE and DataSize = 0, NDIS will allocate a net
    // buffer but not any data buffers when we allocate a net buffer and net
    // buffer list.
    poolParams.fAllocateNetBuffer = TRUE;
    poolParams.ContextSize = 0;
    poolParams.PoolTag = PIA_WFP_TAG;
    poolParams.DataSize = 0;
    g_netBufferListPool = NdisAllocateNetBufferListPool(NULL, &poolParams);
    if(!g_netBufferListPool)
    {
        DEBUG_PRINT("Can't create net buffer list pool");
        DriverUnload(NULL);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

UINT32 ChecksumAccumulate(UINT32 checksumTotal, UINT16 *pData, UINT32 bytes)
{
    UINT16 *pDataEnd = pData + (bytes/sizeof(UINT16));
    while(pData != pDataEnd)
    {
        checksumTotal += *pData;
        ++pData;
    }

    if(bytes % 2)
    {
        UINT16 lastWord = *((UINT8*)pData);
        lastWord <<= 8;
        lastWord = htons(lastWord);
        checksumTotal += lastWord;
    }

    return checksumTotal;
}

UINT16 ChecksumFinish(UINT32 checksumTotal)
{
    checksumTotal = (checksumTotal & 0x0000FFFF) + (checksumTotal >> 16);
    checksumTotal += (checksumTotal >> 16);
    return (UINT16)~checksumTotal;
}

UINT16 CalculateChecksum(UINT16 *pData, UINT32 bytes)
{
    return ChecksumFinish(ChecksumAccumulate(0, pData, bytes));
}

void UpdateIpv4HeaderChecksum(PIPV4_HEADER IpHeader, UINT32 IpHeaderSize)
{
    IpHeader->Checksum = 0;
    IpHeader->Checksum = CalculateChecksum((UINT16*)IpHeader, IpHeaderSize);
}

void UpdateUdp4HeaderChecksum(IPV4_HEADER *pIpHeader, UINT32 ipHeaderSize,
                              UINT32 packetSize)
{
    UDP_HEADER *pUdpHeader = (UDP_HEADER*)(((unsigned char*)pIpHeader) + ipHeaderSize);
    pUdpHeader->Checksum = 0;

    // Construct the IPv4 pseudo-header used by UDP to compute the checksum
    typedef struct _UDP_IPV4_PSEUDOHEADER
    {
        UINT32 SourceAddress;
        UINT32 DestinationAddress;
        UINT8 Zero;
        UINT8 Protocol;
        UINT16 Length;
    } UDP_IPV4_PSEUDOHEADER;

    UDP_IPV4_PSEUDOHEADER pseudoHeader = {0};
    pseudoHeader.SourceAddress = pIpHeader->SourceAddress;
    pseudoHeader.DestinationAddress = pIpHeader->DestinationAddress;
    pseudoHeader.Zero = 0;
    pseudoHeader.Protocol = 0x11;   // UDP
    // The "length" in the checksum is the "UDP length" - length of the UDP
    // header and data
    pseudoHeader.Length = htons((UINT16)(packetSize - ipHeaderSize));

    UINT32 checksumAccum = ChecksumAccumulate(0, (UINT16*)&pseudoHeader, sizeof(pseudoHeader));
    // Accumulate UDP header and UDP data
    checksumAccum = ChecksumAccumulate(checksumAccum, (UINT16*)pUdpHeader, packetSize - ipHeaderSize);
    pUdpHeader->Checksum = ChecksumFinish(checksumAccum);
    // 0 indicates that no checksum was calculated, if the checksum would be 0,
    // send it as 0xFFFF instead (in one's complement, that's "-0", which adds
    // up the same way on the receiving end but indicates the checksum is
    // significant).
    if(pUdpHeader->Checksum == 0)
        pUdpHeader->Checksum = 0xFFFF;
}

// Copy dataSize bytes from pNetBuffer to pOutput, starting at the current
// position.  This wraps NdisGetDataBuffer.
//
// NdisGetDataBuffer() in some cases copies to the output buffer, but it can
// also return a pointer to the original data if the requested data were
// contiguous.  ReadNetBuffer() wraps this so that we always copy the data to
// the output buffer.
//
// - In some cases, we need to modify the data and then use it to inject a new
//   packet.  We need to be sure we're not modifying the original buffer.
// - We usually need to ensure alignment.  NdisGetDataBuffer() takes alignment
//   parameters, but it's not clear from the doc how it applies them - it just
//   says that it will "allocate memory to satisfy the alignment requirement".
//   We would need it to copy the data if it's not aligned (even if the data
//   were contiguous), and the doc does not indicate that it does that.  The
//   only way "allocating memory" would make sense is if it's using that memory
//   to fragment the net buffer and copy the data, there's no point in doing
//   that when we have a stack buffer ready anyway.
BOOL ReadNetBuffer(NET_BUFFER *pNetBuffer, void *pOutput, ULONG dataSize)
{
    void *pRequestedData = NdisGetDataBuffer(pNetBuffer, dataSize, pOutput, 1, 0);
    if(!pRequestedData)
        return FALSE;   // Couldn't obtain the data for some reason
    if(pRequestedData == pOutput)
        return TRUE;    // NdisGetDataBuffer() copied for us
    // Copy the data manually
    memcpy(pOutput, pRequestedData, dataSize);
    return TRUE;
}

// Seek a NET_BUFFER.  Advances or retreats the data starting point.  A positive
// offset advances, a negative offset retreats.
BOOL SeekNetBuffer(NET_BUFFER *pNetBuffer, LONG offset)
{
    if(offset < 0)
    {
        NDIS_STATUS status = NdisRetreatNetBufferDataStart(pNetBuffer, (ULONG)(-offset),
                                                           0, NULL);
        if(!NT_SUCCESS(status))
        {
            DEBUG_PRINT("cannot seek net buffer to offset %l, status %08X\n",
                        offset, status);
            return FALSE;
        }
    }
    else if(offset > 0)
    {
        // Advance always succeeds, no return value to check
        NdisAdvanceNetBufferDataStart(pNetBuffer, (ULONG)(offset), FALSE, NULL);
    }

    return TRUE;
}

// Read data from a NET_BUFFER at an offset from the current starting position
BOOL ReadNetBufferOffset(NET_BUFFER *pNetBuffer, LONG offset, void *pOutput,
                         ULONG dataSize)
{
    // If we can't seek to this offset at all, there's nothing else to do.
    if(!SeekNetBuffer(pNetBuffer, offset))
        return FALSE;
    // Even if the read fails, we should still restore the initial offset in the
    // net buffer
    BOOL readSuccess = ReadNetBuffer(pNetBuffer, pOutput, dataSize);
    // This shouldn't fail - if this is a retreat, we just advanced by offset so
    // there is definitely enough data for the retreat.  If it's an advance,
    // advances never fail.
    if(!SeekNetBuffer(pNetBuffer, -offset))
        return FALSE;
    return readSuccess;
}

enum
{
    IPv4PrintLen = 16,
};

void PrintIPv4N(UINT32 ipv4, char buffer[IPv4PrintLen])
{
    IN_ADDR addr;
    addr.S_un.S_addr = ipv4;
    RtlIpv4AddressToStringA(&addr, buffer);
}

void PrintIPv4H(UINT32 ipv4, char buffer[IPv4PrintLen])
{
    PrintIPv4N(htonl(ipv4), buffer);
}

// A flat buffer used to allocate a new packet for injection.  This consists of
// a raw buffer (allocated from the nonpaged pool), an MDL describing that
// buffer, and a NET_BUFFER_LIST containing the MDL.  Each piece must be freed
// after the packet is injected.
typedef struct _InjectBuffer
{
    MDL *pMdl;
    NET_BUFFER_LIST *pNetBufferList;
    // Followed in memory by packet data
} InjectBuffer;

void *GetInjectBufferData(InjectBuffer *pBuffer)
{
    return ((unsigned char*)pBuffer) + sizeof(InjectBuffer);
}

ULONG GetInjectBufferDataLength(InjectBuffer *pBuffer)
{
    return MmGetMdlByteCount(pBuffer->pMdl);
}

void FreeInjectBuffer(InjectBuffer *pBuffer)
{
    if(!pBuffer)
        return;

    if(pBuffer->pMdl)
        IoFreeMdl(pBuffer->pMdl);

    if(pBuffer->pNetBufferList)
        FwpsFreeNetBufferList(pBuffer->pNetBufferList);

    // Free the InjectBuffer and the attached data buffer
    ExFreePoolWithTag(pBuffer, PIA_WFP_TAG);
}

InjectBuffer *AllocateInjectBuffer(ULONG length)
{
    InjectBuffer *pBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                                  sizeof(InjectBuffer) + length,
                                                  PIA_WFP_TAG);
    if(!pBuffer)
    {
        DEBUG_PRINT("Unable to allocate buffer of length %u\n", length);
        goto failed;
    }

    pBuffer->pMdl = IoAllocateMdl(GetInjectBufferData(pBuffer), length, FALSE,
                                  FALSE, NULL);
    if(!pBuffer->pMdl)
    {
        DEBUG_PRINT("Unable to allocate MDL decribing buffer of length %u\n", length);
        goto failed;
    }

    MmBuildMdlForNonPagedPool(pBuffer->pMdl);

    NDIS_STATUS status = FwpsAllocateNetBufferAndNetBufferList(g_netBufferListPool,
                                                               0, 0,
                                                               pBuffer->pMdl, 0,
                                                               length,
                                                               &pBuffer->pNetBufferList);

    if(!NT_SUCCESS(status) || !pBuffer->pNetBufferList)
    {
        DEBUG_PRINT("Unable to allocate net buffer list for %u bytes, status %08X\n",
                    length, status);
        goto failed;
    }

    return pBuffer;

failed:
    FreeInjectBuffer(pBuffer);
    return NULL;
}

void DebugDumpData(void *pData, ULONG length)
{
    // does nothing in debug
    UNREFERENCED_PARAMETER(pData);  // used only for debug tracing
    UNREFERENCED_PARAMETER(length);  // used only for debug tracing

    UINT32 *pDataWords = pData;
    UNREFERENCED_PARAMETER(pDataWords);  // used only for debug tracing
    ULONG words = length / sizeof(UINT32);
    for(ULONG i=0; i<words; ++i)
    {
        DEBUG_PRINT("%02d: %08X\n", i*sizeof(UINT32), ntohl(pDataWords[i]));
    }
    char *pLastBytes = ((char*)pData) + words * sizeof(UINT32);
    UNREFERENCED_PARAMETER(pLastBytes);  // used only for debug tracing

    switch(length % sizeof(UINT32))
    {
    default:
        break;
    case 1:
        DEBUG_PRINT("%02d: %02X\n", words*sizeof(UINT32), pLastBytes[0]);
        break;
    case 2:
        DEBUG_PRINT("%02d: %02X%02X\n", words*sizeof(UINT32),
                    pLastBytes[0], pLastBytes[1]);
        break;
    case 3:
        DEBUG_PRINT("%02d: %02X%02X%02X\n", words*sizeof(UINT32),
                    pLastBytes[0], pLastBytes[1], pLastBytes[2]);
        break;
    }
}

void NTAPI DriverAllocInjectComplete(
    _In_ void* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
)
{
    UNREFERENCED_PARAMETER(dispatchLevel);

    NTSTATUS injectStatus = netBufferList ? netBufferList->Status : STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(injectStatus))
    {
        DEBUG_PRINT("Inject failed with status %08X\n", injectStatus);
        InjectBuffer *pBuffer = (InjectBuffer*)context;
        void *pData = pBuffer ? GetInjectBufferData(pBuffer) : NULL;
        ULONG length = pBuffer ? GetInjectBufferDataLength(pBuffer) : 0;
        DebugDumpData(pData, length);
    }

    FreeInjectBuffer((InjectBuffer*)context);
}

UINT16 *GetTransportHeaderDest(TRANSPORT_PORT_HEADER *pHdr){return &pHdr->DestinationPort;}
UINT16 *GetTransportHeaderSource(TRANSPORT_PORT_HEADER *pHdr){return &pHdr->SourcePort;}
UINT32 *GetIpHeaderDest(IPV4_HEADER *pHdr){return &pHdr->DestinationAddress;}
UINT32 *GetIpHeaderSource(IPV4_HEADER *pHdr){return &pHdr->SourceAddress;}

// Check if this is a DNS packet - if so, we need to check whether we should
// block or rewrite the packet.
//
// If it is DNS, the IP and transport headers are populated in pIpHeader and
// pTransportHeader, and TRUE is returned.  If it is not DNS at all, FALSE is
// returned (pass the packet unmodified).
BOOL IsDnsPacket(PNET_BUFFER pOrigPktBuf, UINT32 ipHeaderSize,
                 UINT16 *(*getRemotePort)(TRANSPORT_PORT_HEADER*),
                 IPV4_HEADER *pIpHeader,
                 TRANSPORT_PORT_HEADER *pTransportHeader,
                 char dbgDirChar)
{
    UNREFERENCED_PARAMETER(dbgDirChar);

    if(!getRemotePort || !pIpHeader || !pTransportHeader)
        return FALSE;

    // Read the original IPv4 header.  This doesn't include the extension
    // fields, so we can't use this to calculate an IPv4 checksum.
    if(!ReadNetBuffer(pOrigPktBuf, (void*)pIpHeader, sizeof(*pIpHeader)))
    {
        DEBUG_PRINT("(%c): unable to read IPv4 header\n", dbgDirChar);
        return FALSE;
    }

    if(pIpHeader->Protocol != IPPROTO_TCP &&
       pIpHeader->Protocol != IPPROTO_UDP)
    {
        return FALSE; // Not a DNS packet, permit
    }

    // Read the part of the transport header that contains the source/dest ports
    if(!ReadNetBufferOffset(pOrigPktBuf, (LONG)ipHeaderSize, pTransportHeader,
                            sizeof(*pTransportHeader)))
    {
        DEBUG_PRINT("(%c): can't read beginning of transport header\n", dbgDirChar);
        return FALSE;
    }

    UINT16 remotePort = *getRemotePort(pTransportHeader);
    remotePort = ntohs(remotePort);
    if(remotePort != 53)
    {
        return FALSE; // Not a DNS packet, don't care
    }

    // It's a DNS packet (either TCP or UDP).
    return TRUE;
}

// If the packet in pOrigPktBuf is a DNS packet to/from expectedDnsIp, rewrite
// it to rewriteDnsIp, and rewrite the local address to rewriteLocalIp.
//
// All IP addresses are in _host_ byte order.
//
// There are three possible results from this function:
// - returns valid InjectBuffer - absorb packet and re-inject (UDP DNS, rewritten)
// - returns null with pBlock = TRUE - just block packet, nothing to re-inject
//   (TCP DNS, or UDP DNS to unexpected address)
// - returns null with pBlock = FALSE - pass packet (not DNS at all)
//
// If the packet matches and is rewritten, an InjectBuffer is returned that
// should be injected in place of the original packet.  Otherwise, nullptr is
// returned.
//
// For outbound, the remote address is the destination address, and the local
// address is the source address - use &GetIpHeaderDest, &GetIpHeaderSource.
//
// For inbound, the remote is the source, and the local is the destination -
// use &GetIpHeaderSource, &GetIpHeaderDest.
//
// dbgDirChar is used for debug logging, use 'o'/'i' for outbound/inbound.
InjectBuffer *RewriteDnsPacket(PNET_BUFFER pOrigPktBuf, UINT32 ipHeaderSize,
                               IPV4_HEADER *pIpHeader,
                               UINT32 rewriteDnsIp, UINT32 rewriteLocalIp,
                               UINT32 *(*getRemoteAddr)(IPV4_HEADER*),
                               UINT32 *(*getLocalAddr)(IPV4_HEADER*),
                               char dbgDirChar)
{
    UNREFERENCED_PARAMETER(dbgDirChar);

    if(!pOrigPktBuf || !pIpHeader || !getRemoteAddr || !getLocalAddr)
        return NULL;

    // Currently we can only rewrite UDP, although DNS can also be sent over
    // TCP.  If this is a DNS request over TCP, block it to prevent a leak.
    if(pIpHeader->Protocol != IPPROTO_UDP)
    {
        DEBUG_PRINT("(%c): can't rewrite DNS request using transport %d",
                    dbgDirChar, pIpHeader->Protocol);
        return NULL;
    }

    UINT32 origRemote = *getRemoteAddr(pIpHeader);
    origRemote = ntohl(origRemote);
    DEBUG_PRINT("(%c) found a matching packet for rewrite - original remote %08X\n",
                dbgDirChar, origRemote);

    ULONG packetLength = NET_BUFFER_DATA_LENGTH(pOrigPktBuf);
    // Allocate a new NET_BUFFER_LIST of that length and copy the entire
    // packet so we can alter it
    InjectBuffer *pInjectPacket = AllocateInjectBuffer(packetLength);
    if(!pInjectPacket)
    {
        DEBUG_PRINT("(%c): unable to allocate new packet of length %d\n",
                    dbgDirChar, packetLength);
        return NULL;
    }

    if(!ReadNetBuffer(pOrigPktBuf, GetInjectBufferData(pInjectPacket), packetLength))
    {
        DEBUG_PRINT("(%c): unable to copy packet data to inject packet of length %d\n",
                    dbgDirChar, packetLength);
        FreeInjectBuffer(pInjectPacket);
        return NULL;
    }

    IPV4_HEADER *pInjectIpHeader = (IPV4_HEADER*)GetInjectBufferData(pInjectPacket);
    *getRemoteAddr(pInjectIpHeader) = htonl(rewriteDnsIp);
    *getLocalAddr(pInjectIpHeader) = htonl(rewriteLocalIp);
    DEBUG_PRINT("(%c) Rewrote DNS packet from %08X to %08X\n",
                dbgDirChar, origRemote, rewriteDnsIp);
    UpdateIpv4HeaderChecksum(pInjectIpHeader, ipHeaderSize);
    UpdateUdp4HeaderChecksum(pInjectIpHeader, ipHeaderSize, packetLength);

    return pInjectPacket;
}

void NTAPI DriverIpPacketOutboundClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // This is a terminating callout, we must return an action.  Permit by
    // default unless we rewrite the packet.
    classifyOut->actionType = FWP_ACTION_PERMIT;

    // If the packet was injected by us, do nothing
    if(injectedBySelf(layerData))
        return;

    if(!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE))
    {
        DEBUG_PRINT("(o): packet metadata missing IP header size - received value flags: %08X\n",
                    inMetaValues->currentMetadataValues);
        return;
    }

    // Check if the packet is a DNS packet.
    PNET_BUFFER pOrigPktBuf = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)layerData);
    IPV4_HEADER ipHeader = {0};
    TRANSPORT_PORT_HEADER transportHeader = {0};
    if(!IsDnsPacket(pOrigPktBuf, inMetaValues->ipHeaderSize,
                    &GetTransportHeaderDest, &ipHeader, &transportHeader, 'o'))
    {
        // It's not a DNS packet, pass it.
        return;
    }

    // It's a DNS packet - look in the flow cache to see if we should rewrite or
    // block it.
    DnsFlow outboundFlow = {0};
    outboundFlow.actualLocalIp = ntohl(ipHeader.SourceAddress);
    outboundFlow.actualRemoteIp = ntohl(ipHeader.DestinationAddress);
    outboundFlow.localPort = ntohs(transportHeader.SourcePort);
    // Provide the interface and subinterface indices, since these are known
    // at the outbound packet layer - if this is a flow we care about, we'll
    // store them for the inbound rewrite.
    outboundFlow.actualInterfaceIdx = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32;
    outboundFlow.actualSubinterfaceIdx = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32;

    if(!DnsFlow_FindOutbound(&outboundFlow))
    {
        DEBUG_PRINT("(o): no match for DNS flow %08X:%d -> %08X",
                    outboundFlow.actualLocalIp, outboundFlow.localPort,
                    outboundFlow.actualRemoteIp);
        return; // Not a flow we need to rewrite
    }

    // DnsFlow_FindOutbound() provided the intended local/remote IPs - rewrite
    // the packet and reinject.
    InjectBuffer *pRewrittenPacket = RewriteDnsPacket(pOrigPktBuf,
                                                      inMetaValues->ipHeaderSize,
                                                      &ipHeader,
                                                      outboundFlow.intendedRemoteIp,
                                                      outboundFlow.intendedLocalIp,
                                                      &GetIpHeaderDest,
                                                      &GetIpHeaderSource, 'o');

    if(pRewrittenPacket)
    {
        NDIS_STATUS injectStatus = FwpsInjectNetworkSendAsync(g_injectionHandle, NULL, 0,
                                                              inMetaValues->compartmentId,
                                                              pRewrittenPacket->pNetBufferList,
                                                              DriverAllocInjectComplete,
                                                              pRewrittenPacket);
        if (!NT_SUCCESS(injectStatus))
        {
            DEBUG_PRINT("(o): failed FwpsInjectNetworkSendAsync - %08X\n",
                        injectStatus);
            FreeInjectBuffer(pRewrittenPacket);
        }
        else
        {
            // We modified and reinjected the packet; absorb the original.  (A
            // block action is applied below since blockOriginal is set, apply
            // the absorb flag since we were able to reinject.)
            classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        }
    }

    // Block the original packet.  If a reinject was successfully performed,
    // the absorb flag is already set; otherwise we weren't able to reinject
    // so we want the app to know that this was dropped.
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

void NTAPI DriverIpPacketInboundClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // This is a terminating callout, we must return an action.  Permit by
    // default unless we rewrite the packet.
    classifyOut->actionType = FWP_ACTION_PERMIT;

    // If the packet was injected by us, do nothing
    if(injectedBySelf(layerData))
        return;

    if(!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE))
    {
        DEBUG_PRINT("(i): packet metadata missing IP header size - received value flags: %08X\n",
                    inMetaValues->currentMetadataValues);
        return;
    }

    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;

    PNET_BUFFER pOrigPktBuf = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)layerData);

    // Oddly, data in the INBOUND_IPPACKET_V4 layer starts at the transport
    // header, unlike OUTBOUND_IPPACKET_V4.  Go back to the IP header.
    NDIS_STATUS retreatStatus = NdisRetreatNetBufferDataStart(pOrigPktBuf,
                                                              inMetaValues->ipHeaderSize,
                                                              0, NULL);
    if(!NT_SUCCESS(retreatStatus))
    {
        DEBUG_PRINT("(i): unable to read IPv4 header: %08X\n", retreatStatus);
        return;
    }

    // Check if the packet is a DNS packet.
    IPV4_HEADER ipHeader = {0};
    TRANSPORT_PORT_HEADER transportHeader = {0};
    if(!IsDnsPacket(pOrigPktBuf, inMetaValues->ipHeaderSize,
                    &GetTransportHeaderSource, &ipHeader, &transportHeader, 'i'))
    {
        // It's not a DNS packet, pass it.
        NdisAdvanceNetBufferDataStart(pOrigPktBuf, inMetaValues->ipHeaderSize, FALSE, NULL);
        return;
    }

    // It's a DNS packet - look in the flow cache to see if this is a flow that
    // we are rewriting.
    DnsFlow inboundFlow = {0};
    inboundFlow.intendedLocalIp = ntohl(ipHeader.DestinationAddress);
    inboundFlow.intendedRemoteIp = ntohl(ipHeader.SourceAddress);
    inboundFlow.localPort = ntohs(transportHeader.DestinationPort);

    if(!DnsFlow_FindInbound(&inboundFlow))
    {
        NdisAdvanceNetBufferDataStart(pOrigPktBuf, inMetaValues->ipHeaderSize, FALSE, NULL);
        return; // Not a flow we need to rewrite
    }

    // DnsFlow_FindInbound() provided the actual local/remote IPs and the
    // interface/subinterface indices.
    InjectBuffer *pRewrittenPacket = RewriteDnsPacket(pOrigPktBuf,
                                                      inMetaValues->ipHeaderSize,
                                                      &ipHeader,
                                                      inboundFlow.actualRemoteIp,
                                                      inboundFlow.actualLocalIp,
                                                      &GetIpHeaderSource,
                                                      &GetIpHeaderDest, 'i');
    NdisAdvanceNetBufferDataStart(pOrigPktBuf, inMetaValues->ipHeaderSize, FALSE, NULL);
    if(pRewrittenPacket)
    {
        NDIS_STATUS injectStatus = FwpsInjectNetworkReceiveAsync(g_injectionHandle, NULL, 0,
                                                                 inMetaValues->compartmentId,
                                                                 inboundFlow.actualInterfaceIdx,
                                                                 inboundFlow.actualSubinterfaceIdx,
                                                                 pRewrittenPacket->pNetBufferList,
                                                                 DriverAllocInjectComplete,
                                                                 pRewrittenPacket);
        if(!NT_SUCCESS(injectStatus))
        {
            DEBUG_PRINT("(i): failed FwpsInjectNetworkReceiveAsync - %08X\n",
                        injectStatus);
            FreeInjectBuffer(pRewrittenPacket);
        }
        else
        {
            // We modified and reinjected the packet; absorb the original.  (A
            // block action is applied below since blockOriginal is set, apply
            // the absorb flag since we were able to reinject.)
            classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        }
    }

    // Block the original packet.  If a reinject was successfully performed,
    // the absorb flag is already set; otherwise we weren't able to reinject
    // so we want the app to know that this was dropped.
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

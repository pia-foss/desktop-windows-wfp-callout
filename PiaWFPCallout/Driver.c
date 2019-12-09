// Copyright (c) 2019 London Trust Media Incorporated
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
UINT32 CalloutId;
WDFDEVICE wdfDevice;

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD DriverUnload;
EVT_WDF_DRIVER_DEVICE_ADD PiaWFPEvtDeviceAdd;

DEFINE_GUID(
	PIA_WFP_CALLOUT_V4,
	0xb16b0a6e,
	0x2b2a,
	0x41a3,
	0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8
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

	NT_ASSERT(inFixedValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V4);
	NT_ASSERT(filter->providerContext);
	NT_ASSERT(filter->providerContext->dataBuffer);
	NT_ASSERT(filter->providerContext->dataBuffer->data);

	NTSTATUS status;

	if(layerData && classifyContext)
	{
		if(inFixedValues->layerId != FWPS_LAYER_ALE_BIND_REDIRECT_V4)
		{
			return;
		}

		if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE &&
			!(inFixedValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_FLAGS].value.uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE))
		{
			if (filter->providerContext)
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: provider context exists\n"));
			}
			else
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: no provider context\n"));
			}

			IN_ADDR originalSourceIp = { 0 };
			IN_ADDR newSourceIp = { 0 };

			originalSourceIp.S_un.S_addr = inFixedValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_LOCAL_ADDRESS].value.uint32;
			newSourceIp.S_un.S_addr = htonl(*(UINT32*)(filter->providerContext->dataBuffer->data));

			// Do nothing if we have a loopback IP (i.e 127/8)
			if(*(unsigned char*) &originalSourceIp == 127)
				return;

			UINT64 classifyHandle = 0;
			FWPS_BIND_REQUEST *bindRequest;
			
			status = FwpsAcquireClassifyHandle((void *)classifyContext, 0, &classifyHandle);
			if(!NT_SUCCESS(status))
			{ 
				return;
			}

			status = FwpsAcquireWritableLayerDataPointer(classifyHandle, filter->filterId, 0, &bindRequest, classifyOut);
			if(!NT_SUCCESS(status))
			{
				FwpsReleaseClassifyHandle(classifyHandle);
				return;
			}

			char originalSourceIpStr[32];
			char newSourceIpStr[32];
			RtlIpv4AddressToStringA(&originalSourceIp, originalSourceIpStr);
			RtlIpv4AddressToStringA(&newSourceIp, newSourceIpStr);
		
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: original ipv4: %s\n", originalSourceIpStr));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: new ipv4: %s\n", newSourceIpStr));

			// Rewrite the ip address to the one provided - then via the 'strong host model' packets from this socket will get routed out the interface with this ip
			INETADDR_SET_ADDRESS((PSOCKADDR) &(bindRequest->localAddressAndPort), (BYTE*)&newSourceIp);

			classifyOut->actionType = FWP_ACTION_PERMIT;
			classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
			
			FwpsApplyModifiedLayerData(classifyHandle, &bindRequest, 0);
			FwpsReleaseClassifyHandle(classifyHandle);
		}
	}

	return;
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

	NTSTATUS status;

	// Unregister the callout
	status = FwpsCalloutUnregisterById0(CalloutId);

	if(!NT_SUCCESS(status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PIA_CALLOUT: could not unload driver, status code: %d\n", status));
		return;
	}

	// Delete the framework device object
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

	sCallout.calloutKey = PIA_WFP_CALLOUT_V4;
	sCallout.classifyFn = ClassifyFn;
	sCallout.notifyFn = NotifyFn;

	status =
		FwpsCalloutRegister1(
			deviceObject,
			&sCallout,
			&CalloutId
		);

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

/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	USBFilterDriver.c

Abstract:

	This filter monitors USB device connections.

Environment:

	Kernel mode

--*/

#include <wdm.h>
#include <wdf.h>

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
USBFilterDeviceAddEvt(
	_In_ WDFDRIVER Driver,
	_Inout_ PWDFDEVICE_INIT DeviceInit
);

VOID
USBFilterEvtDeviceControl(
	_In_ WDFQUEUE Queue,
	_In_ WDFREQUEST Request,
	_In_ size_t OutputBufferLength,
	_In_ size_t InputBufferLength,
	_In_ ULONG IoControlCode
);

NTSTATUS
PnpQueryDeviceCallback(
	IN WDFDEVICE Device,
	IN PIRP Irp
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, USBFilterDeviceAddEvt)
#pragma alloc_text (PAGE, USBFilterEvtDeviceControl)
#pragma alloc_text (PAGE, PnpQueryDeviceCallback)
#endif

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

	This is the initialization routine for this Keysas driver.

Arguments:

	DriverObject - Pointer to driver object created by the system to
		represent this driver.

	RegistryPath - Unicode string identifying where the parameters for this
		driver are located in the registry.

Return Value:

	Returns STATUS_SUCCESS.

--*/
{
	WDF_DRIVER_CONFIG config = { 0 };

	NTSTATUS status = STATUS_SUCCESS;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!DriverEntry: Entered\n"));

	WDF_DRIVER_CONFIG_INIT(&config, USBFilterDeviceAddEvt);

	status = WdfDriverCreate(
		DriverObject,
		RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES,
		&config,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!DriverEntry: WdfDriverCreate failed with status: %0x8x\n",
			status));
	}

	return status;
}

NTSTATUS
USBFilterDeviceAddEvt(
	_In_ WDFDRIVER Driver,
	_Inout_ PWDFDEVICE_INIT DeviceInit
)
/*++

Routine Description:

	Called by the system when a new device is found

Arguments:

	Driver - Pointer to our driver

	DeviceInit - New device initialization structure

Return Value:

	Returns STATUS_SUCCESS.

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	WDFDEVICE wdfDevice = { 0 };
	WDF_IO_QUEUE_CONFIG ioQueueConfig = { 0 };
	WDF_OBJECT_ATTRIBUTES wdfObjectAttr = { 0 };
	UCHAR minorFunctions = 0;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!USBFilterDeviceAddEvt: Entered\n"));

	// Set the new instance as a filter
	WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);
	WdfFdoInitSetFilter(DeviceInit);

	minorFunctions = IRP_MN_QUERY_DEVICE_RELATIONS;
	status = WdfDeviceInitAssignWdmIrpPreprocessCallback(
		DeviceInit,
		PnpQueryDeviceCallback,
		IRP_MJ_PNP,
		&minorFunctions,
		1
	);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!USBFilterDeviceAddEvt: WdfDeviceInitAssignWdmIrpPreprocessCallback failed with status: %0x8x\n",
			status));
		goto cleanup;
	}

	WDF_OBJECT_ATTRIBUTES_INIT(&wdfObjectAttr);

	// Create the new instance for the device
	status = WdfDeviceCreate(
		&DeviceInit,
		&wdfObjectAttr,
		&wdfDevice
	);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!USBFilterDeviceAddEvt: WdfDeviceCreate failed with status: %0x8x\n",
			status));
		goto cleanup;
	}

	// Create a queue to handle the requests
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&ioQueueConfig,
		WdfIoQueueDispatchParallel
	);

	ioQueueConfig.EvtIoDeviceControl = USBFilterEvtDeviceControl;

	status = WdfIoQueueCreate(
		wdfDevice,
		&ioQueueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!USBFilterDeviceAddEvt: WdfIoQueueCreate failed with status: %0x8x\n",
			status));
		goto cleanup;
	}

cleanup:

	return status;
}

VOID
USBFilterEvtDeviceControl(
	_In_ WDFQUEUE Queue,
	_In_ WDFREQUEST Request,
	_In_ size_t OutputBufferLength,
	_In_ size_t InputBufferLength,
	_In_ ULONG IoControlCode
)
/*++

Routine Description:

	Handler for I/O request to the device

Arguments:

	Queue - Pointer to the framework queue

	Request - Pointer to the request

	OutputBufferLength - Length, in bytes, of the request's output buffer

	InputBufferLength - Length, in bytes, of the request's input buffer

	IoControlCode - IOCTL associated with the request

Return Value:

	Returns STATUS_SUCCESS.

--*/
{
	WDF_REQUEST_SEND_OPTIONS sendOpts = { 0 };
	WDFDEVICE wdfDevice = NULL;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);

	PAGED_CODE();

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!USBFilterEvtDeviceControl: Entered\n"));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!USBFilterEvtDeviceControl: Request 0x%p - IoControlCode 0x%p\n",
		Request, IoControlCode));

	WDF_REQUEST_SEND_OPTIONS_INIT(&sendOpts, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

	wdfDevice = WdfIoQueueGetDevice(Queue);

	if (!WdfRequestSend(Request, WdfDeviceGetIoTarget(wdfDevice), &sendOpts)) {
		status = WdfRequestGetStatus(Request);
		WdfRequestComplete(Request, STATUS_SUCCESS);

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!USBFilterEvtDeviceControl: WdfRequestSend failed\n"));
	}

}

NTSTATUS
PnpQueryDeviceCallback(
	IN WDFDEVICE Device,
	IN PIRP Irp
)
/*++

Routine Description:

	This routine is called when a IRP_MN_QUERY_DEVICE_RELATIONS is received

Arguments:

	DeviceObject - Pointer to the device object for this device

	Irp - Pointer to the IRP for the current request

Return Value:

	The function value is the final status of the call

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack = NULL;


	PAGED_CODE();

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!PnpQueryDeviceCallback: Entered\n"));

	// No callback for post processing the IRP
	IoSkipCurrentIrpStackLocation(Irp);

	status = WdfDeviceWdmDispatchPreprocessedIrp(
		Device,
		Irp
	);

	return status;
}
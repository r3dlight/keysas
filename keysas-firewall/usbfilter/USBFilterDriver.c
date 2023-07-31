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

/*---------------------------------------
-
- Global definitions
-
-----------------------------------------*/
#define KEYSAS_USBFILTER_POOL_TAG 'FUeK'


/*---------------------------------------
-
- Function declarations
-
-----------------------------------------*/

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
KUFDeviceAddEvt(
	_In_ WDFDRIVER Driver,
	_Inout_ PWDFDEVICE_INIT DeviceInit
);

VOID
KUFEvtDeviceControl(
	_In_ WDFQUEUE Queue,
	_In_ WDFREQUEST Request,
	_In_ size_t OutputBufferLength,
	_In_ size_t InputBufferLength,
	_In_ ULONG IoControlCode
);

NTSTATUS
KUFPnpQueryDeviceCallback(
	IN WDFDEVICE Device,
	IN PIRP Irp
);

NTSTATUS
KUFGetDeviceInfo(
	_In_ PDEVICE_OBJECT Device,
	_In_ BUS_QUERY_ID_TYPE Type,
	_Outptr_opt_ PWCHAR* Information
);

NTSTATUS
KUFIsUsbHub(
	_In_ PDEVICE_OBJECT Device,
	_Out_ PBOOLEAN IsHub
);

IO_COMPLETION_ROUTINE KUFDeviceRelationsPostProcessing;

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KUFDeviceAddEvt)
#pragma alloc_text (PAGE, KUFEvtDeviceControl)
#pragma alloc_text (PAGE, KUFPnpQueryDeviceCallback)
#pragma alloc_text (PAGE, KUFGetDeviceInfo)
#pragma alloc_text (PAGE, KUFIsUsbHub)
#endif

/*---------------------------------------
-
- Function implementations
-
-----------------------------------------*/

NTSTATUS
KUFGetDeviceInfo(
	_In_ PDEVICE_OBJECT Device,
	_In_ BUS_QUERY_ID_TYPE Type,
	_Outptr_opt_ PWCHAR * Information
)
/*++
Routine Description:
	This routine is called to get information on a PDO

Arguments:
	Device - Pointer to the target device
	Type - Type of information requested
	Information - Output pointer for the information. It is allocated by the function

Return Value:
	Return STATUS_SUCCESS

IRQL:
	Must be called at PASSIVE_LEVEL
--*/
{
	NTSTATUS result = STATUS_UNSUCCESSFUL;
	KEVENT ke;
	IO_STATUS_BLOCK ios = { 0 };
	PIRP irp = NULL;
	PIO_STACK_LOCATION stack = NULL;
	NTSTATUS nts = STATUS_UNSUCCESSFUL;
	size_t bufferLength = 0;

	// Test inputs provided
	if (NULL == Device || NULL == Information) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFGetDeviceInfo: Invalid inputs\n"));
		goto cleanup;
	}

	KeInitializeEvent(&ke, NotificationEvent, FALSE);

	irp = IoBuildSynchronousFsdRequest(
		IRP_MJ_PNP,
		Device,
		NULL,
		0,
		NULL,
		&ke,
		&ios
	);

	if (NULL == irp) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFGetDeviceInfo: Failed to allocate IRP\n"));
		goto cleanup;
	}

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	stack = IoGetNextIrpStackLocation(irp);

	if (NULL == stack) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFGetDeviceInfo: Failed to get stack location\n"));
		goto cleanup;
	}

	stack->MinorFunction = IRP_MN_QUERY_ID;
	stack->Parameters.QueryId.IdType = Type;

	nts = IoCallDriver(Device, irp);

	if (STATUS_PENDING == nts) {
		KeWaitForSingleObject(&ke, Executive, KernelMode, FALSE, NULL);
	}

	if (NT_SUCCESS(nts)) {
		bufferLength = (wcslen((WCHAR*)ios.Information)+1) * sizeof(WCHAR);
		*Information = (PWCHAR)ExAllocatePool2(NonPagedPool, bufferLength, KEYSAS_USBFILTER_POOL_TAG);
		if (NULL != *Information) {
			RtlCopyMemory(*Information, (PWCHAR) ios.Information, bufferLength - 2);
			result = STATUS_SUCCESS;
		}
		else {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFGetDeviceInfo: Failed to allocate output buffer\n"));
		}
	}

cleanup:

	return result;
}

NTSTATUS
KUFIsUsbHub(
	_In_ PDEVICE_OBJECT Device,
	_Out_ PBOOLEAN IsHub
)
/*++
Routine Description:
	This routine test if a physical device is a USB root Hub
	The decision is made on the Device ID. For USB root hubs it starts with:
	"USB\ROOT_HUB', "NUSB3\ROOT_HUB" or "IUSB3\ROOT_HUB"
	TODO - Verify the exhaustivity of the list

Arguments:
	Device - Pointer to the device to test
	IsHub - Boolean containing the result of the test

Return:
	Returns STATUS_SUCCESS if no error occured.

IRQL:
	Must be called at PASSIVE_LEVEL
--*/
{
	NTSTATUS result = STATUS_UNSUCCESSFUL;
	PWCHAR deviceId = NULL;

	// Test inputs
	if (NULL == Device || NULL == IsHub) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFIsUsbHub: Invalid inputs\n"));
		goto cleanup;
	}
	// Set default to FALSE
	*IsHub = FALSE;

	// Get DeviceID
	if (STATUS_SUCCESS != KUFGetDeviceInfo(
		Device,
		BusQueryDeviceID,
		&deviceId
	)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFIsUsbHub: Failed to get Device ID\n"));
		goto cleanup;
	}

	// Compare with reference strings
	if (!wcsncmp(deviceId, L"USB\\ROOT_HUB", 13)
		|| !wcsncmp(deviceId, L"NUSB3\\ROOT_HUB", 15)
		|| !wcsncmp(deviceId, L"IUSB3\\ROOT_HUB", 15)) {
		// It is a USB Hub
		*IsHub = TRUE;
	}

	result = STATUS_SUCCESS;

cleanup:
	if (NULL != deviceId) {
		ExFreePoolWithTag(deviceId, KEYSAS_USBFILTER_POOL_TAG);
	}

	return result;
}

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

IRQL:
	Routine called at PASSIVE_LEVEL in system thread context.
--*/
{
	WDF_DRIVER_CONFIG config = { 0 };

	NTSTATUS status = STATUS_SUCCESS;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!DriverEntry: Entered\n"));

	WDF_DRIVER_CONFIG_INIT(&config, KUFDeviceAddEvt);

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

	status = STATUS_SUCCESS;

	return status;
}

NTSTATUS
KUFDeviceAddEvt(
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

IRQL:
	Routine called at PASSIVE_LEVEL in system thread context.
--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	WDFDEVICE wdfDevice = { 0 };
	WDF_IO_QUEUE_CONFIG ioQueueConfig = { 0 };
	WDF_OBJECT_ATTRIBUTES wdfObjectAttr = { 0 };
	UCHAR minorFunctions = 0;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFDeviceAddEvt: Entered\n"));

	// Set the new instance as a filter
	WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);
	WdfFdoInitSetFilter(DeviceInit);

	minorFunctions = IRP_MN_QUERY_DEVICE_RELATIONS;
	status = WdfDeviceInitAssignWdmIrpPreprocessCallback(
		DeviceInit,
		KUFPnpQueryDeviceCallback,
		IRP_MJ_PNP,
		&minorFunctions,
		1
	);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFDeviceAddEvt: WdfDeviceInitAssignWdmIrpPreprocessCallback failed with status: %0x8x\n",
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
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFDeviceAddEvt: WdfDeviceCreate failed with status: %0x8x\n",
			status));
		goto cleanup;
	}

	// Create a queue to handle the requests
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&ioQueueConfig,
		WdfIoQueueDispatchParallel
	);

	ioQueueConfig.EvtIoDeviceControl = KUFEvtDeviceControl;

	status = WdfIoQueueCreate(
		wdfDevice,
		&ioQueueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFDeviceAddEvt: WdfIoQueueCreate failed with status: %0x8x\n",
			status));
		goto cleanup;
	}

	status = STATUS_SUCCESS;

cleanup:

	return status;
}

VOID
KUFEvtDeviceControl(
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

IRQL:
	Can be called at IRQL <= DISPATCH_LEVEL
--*/
{
	WDF_REQUEST_SEND_OPTIONS sendOpts = { 0 };
	WDFDEVICE wdfDevice = NULL;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(IoControlCode);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFEvtDeviceControl: Entered\n"));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFEvtDeviceControl: Request 0x%p - IoControlCode 0x%p\n",
		Request, IoControlCode));

	WDF_REQUEST_SEND_OPTIONS_INIT(&sendOpts, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

	wdfDevice = WdfIoQueueGetDevice(Queue);

	if (!WdfRequestSend(Request, WdfDeviceGetIoTarget(wdfDevice), &sendOpts)) {
		status = WdfRequestGetStatus(Request);
		WdfRequestComplete(Request, STATUS_SUCCESS);

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFEvtDeviceControl: WdfRequestSend failed\n"));
	}

}

_Use_decl_annotations_
NTSTATUS
KUFDeviceRelationsPostProcessing(
	PDEVICE_OBJECT Device,
	PIRP Irp,
	PVOID Context
)
/*++
Routine Description:
	Completion routine called to filter device relations list provided by USB hubs to the PNP Manager

Arguments:
	Device - Pointer to the device object
	Irp - Pointer to the IRP for the current request
	Context - Additional data passed in the pre process stage, not used
--*/
{
	NTSTATUS result = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Device);
	UNREFERENCED_PARAMETER(Irp);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFDeviceRelationsPostProcessing: Entered\n"));

	return result;
}

NTSTATUS
KUFPnpQueryDeviceCallback(
	IN WDFDEVICE Device,
	IN PIRP Irp
)
/*++
Routine Description:
	This routine is called when a IRP_MN_QUERY_DEVICE_RELATIONS is received

Arguments:
	Device - Pointer to the device object for this device
	Irp - Pointer to the IRP for the current request

Return Value:
	The function value is the final status of the call

IRQL:
	Is called at the IRQL of the IRP calling thread
--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack = NULL;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas - USBFilter!KUFPnpQueryDeviceCallback: Entered\n"));
	irpStack = IoGetCurrentIrpStackLocation(Irp);

	if (NULL != irpStack
		&& BusRelations == irpStack->Parameters.QueryDeviceRelations.Type) {
		// Register a callback to filter the list of devices returned by the hub
		IoCopyCurrentIrpStackLocationToNext(Irp);

		IoSetCompletionRoutine(
			Irp,
			KUFDeviceRelationsPostProcessing,
			NULL, // No context
			TRUE, // Call on successful IRP
			FALSE, // Don't invoke on error
			FALSE // Dont't invoke on canceled IRP
		);
	}
	else {
		// No callback for post processing the IRP
		// Return the IRP to the framework
		IoSkipCurrentIrpStackLocation(Irp);
	}	

	status = WdfDeviceWdmDispatchPreprocessedIrp(
		Device,
		Irp
	);

	return status;
}
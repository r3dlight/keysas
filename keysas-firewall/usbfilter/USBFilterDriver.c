/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	USBFilterDriver.c

Abstract:

	This filter monitors USB device connections.

Environment:

	Kernel mode

--*/

#include <ntifs.h>
#include <wdm.h>
#include <wdf.h>
#include <usb.h>
#include <usbdlib.h>
#include <wdfusb.h>
#include <usbioctl.h>

/*---------------------------------------
-
- Global definitions
-
-----------------------------------------*/
#define KEYSAS_USBFILTER_POOL_TAG 'FUeK'

/*---------------------------------------
-
- Type definitions
-
-----------------------------------------*/

typedef struct _KEYSAS_USBFILTER_CONTEXT {
	WDFQUEUE NotificationQueue;
	// TODO - add access protection to the queue via a Resource
} KEYSAS_USBFILTER_CONTEXT, * PKEYSAS_USBFILTER_CONTEXT;

/*---------------------------------------
-
- Function declarations
-
-----------------------------------------*/

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_DEVICE_ADD KUFDeviceAddEvt;

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
		DbgPrint("\nKeysas - USBFilter!KUFGetDeviceInfo: Invalid inputs\n");
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
		DbgPrint("\nKeysas - USBFilter!KUFGetDeviceInfo: Failed to allocate IRP\n");
		goto cleanup;
	}

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	stack = IoGetNextIrpStackLocation(irp);

	if (NULL == stack) {
		DbgPrint("\nKeysas - USBFilter!KUFGetDeviceInfo: Failed to get stack location\n");
		goto cleanup;
	}

	stack->MinorFunction = IRP_MN_QUERY_ID;
	stack->Parameters.QueryId.IdType = Type;

	nts = IoCallDriver(Device, irp);

	if (STATUS_PENDING == nts) {
		KeWaitForSingleObject(&ke, Executive, KernelMode, FALSE, NULL);
	}

	if (NT_SUCCESS(nts) && (STATUS_SUCCESS == ios.Status)) {
		bufferLength = (wcslen((WCHAR*)ios.Information) + 1) * sizeof(WCHAR);
		*Information = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferLength, KEYSAS_USBFILTER_POOL_TAG);
		if (NULL != *Information) {
			RtlCopyMemory(*Information, (PWCHAR)ios.Information, bufferLength - 2);
			result = STATUS_SUCCESS;
		}
		else {
			DbgPrint("\nKeysas - USBFilter!KUFGetDeviceInfo: Failed to allocate output buffers\n");
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
		DbgPrint("\nKeysas - USBFilter!KUFIsUsbHub: Invalid inputs\n");
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
		DbgPrint("\nKeysas - USBFilter!KUFIsUsbHub: Failed to get Device ID\n");
		goto cleanup;
	}

	DbgPrint("\nKeysas - USBFilter!KUFIsUsbHub: Device ID: %wS\n", deviceId);

	// Compare with reference strings
	if (!wcscmp(deviceId, L"USB\\ROOT_HUB")
		|| !wcscmp(deviceId, L"USB\\ROOT_HUB20")
		|| !wcscmp(deviceId, L"USB\\ROOT_HUB30")
		|| !wcscmp(deviceId, L"NUSB3\\ROOT_HUB30")
		|| !wcscmp(deviceId, L"IUSB3\\ROOT_HUB30")) {
		// It is a USB Hub
		*IsHub = TRUE;
		DbgPrint("\nKeysas - USBFilter!KUFIsUsbHub: is a hub\n");
	}

	result = STATUS_SUCCESS;

cleanup:
	if (NULL != deviceId) {
		ExFreePoolWithTag(deviceId, KEYSAS_USBFILTER_POOL_TAG);
		deviceId = NULL;
	}

	return result;
}

NTSTATUS
KUFIsUsbMassStorage(
	_In_ PDEVICE_OBJECT Device,
	_Out_ PBOOLEAN IsMassStorage
)
/*++
Routine Description:
	This routine test if a physical device is a USB Mass Storage device
	The decision is made on the device Compatible ID used by the PnP Manager to determine which driver to use for the device.
	Mass Storage device have a Class of value 0x08.
	So the returned is of the form "USB\Class_08..."

Arguments:
	Device - Pointer to the device to test
	IsMassStorage - Boolean containing the result of the test

Return:
	Returns STATUS_SUCCESS if no error occured.

IRQL:
	Must be called at PASSIVE_LEVEL
--*/
{
	NTSTATUS result = STATUS_UNSUCCESSFUL;
	PWCHAR compatibleId = NULL;

	// Test inputs
	if (NULL == Device || NULL == IsMassStorage) {
		DbgPrint("\nKeysas - USBFilter!KUFIsUsbMassStorage: Invalid inputs\n");
		goto cleanup;
	}
	// Set default to FALSE
	*IsMassStorage = FALSE;

	// Get device CompatibleID
	if (STATUS_SUCCESS != KUFGetDeviceInfo(
		Device,
		BusQueryCompatibleIDs,
		&compatibleId
	)) {
		DbgPrint("\nKeysas - USBFilter!KUFIsUsbMassStorage: Failed to get Compatible ID\n");
		goto cleanup;
	}

	DbgPrint("\nKeysas - USBFilter!KUFIsUsbMassStorage: Compatible ID: %wS\n", compatibleId);

	// Compare with reference strings
	if (!wcscmp(compatibleId, L"USB\\Class_08")) {
		// It is a USB Hub
		*IsMassStorage = TRUE;
		DbgPrint("\nKeysas - USBFilter!KUFIsUsbMassStorage: is a Mass Storage device\n");
	}

	result = STATUS_SUCCESS;

cleanup:
	if (NULL != compatibleId) {
		ExFreePoolWithTag(compatibleId, KEYSAS_USBFILTER_POOL_TAG);
		compatibleId = NULL;
	}

	return result;
}
  
NTSTATUS SyncCompletionRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP           Irp,
	_In_ PVOID          Context)
/*++
Routine Description:
	Completion routine for URB submissions

Arguments:
	DeviceObject - Pointer to the driver device object
	Irp - Pointer to the IRP being completed
	Context - Data passed by the IRP calling method.

Return:
	STATUS_MORE_PROCESSING_REQUIRED to return completion to the calling method
--*/
{
	PKEVENT kevent = NULL;

	UNREFERENCED_PARAMETER(DeviceObject);

	kevent = (PKEVENT)Context;

	if (Irp->PendingReturned == TRUE)
	{
		KeSetEvent(kevent, IO_NO_INCREMENT, FALSE);
	}

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS SubmitUrbSync(
	_In_ PDEVICE_OBJECT UsbPDO,
	_In_ USBD_HANDLE UsbDevice,
	_In_ PURB Urb)
/*++
Routine Description:
	Submits a URB synchronously

Arguments:
	UsbPDO - Pointer to the target USB device
	UsbDevice - Handle to the target USB device
	Urb - Pointer to the URB to submit

Return Value:
	STATUS_SUCCESS or error code

IRQL:
	Must be called at PASSIVE_LEVEL
--*/
{

	NTSTATUS  ntStatus = STATUS_SUCCESS;
	KEVENT    kEvent = { 0 };
	PIRP irp = NULL;
	PIO_STACK_LOCATION nextStack = NULL;

	// Validate inputs
	if (NULL == UsbPDO || NULL == UsbDevice || NULL == Urb) {
		DbgPrint("\nKeysas - USBFilter!SubmitUrbSync: Invalid inputs\n");
		ntStatus = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	// Allocate an IRP
	irp = IoAllocateIrp(UsbPDO->StackSize, TRUE);

	if (NULL == irp) {
		DbgPrint("\nKeysas - USBFilter!SubmitUrbSync: failed to allocate IRP\n");
		ntStatus = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	// Get the next stack location.
	nextStack = IoGetNextIrpStackLocation(irp);

	if (NULL == nextStack) {
		DbgPrint("\nKeysas - USBFilter!SubmitUrbSync: failed to get next stack location\n");
		ntStatus = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	// Set the major code.
	nextStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;

	// Set the IOCTL code for URB submission.
	nextStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;

	// Attach the URB to this IRP.
	USBD_AssignUrbToIoStackLocation(UsbDevice, nextStack, Urb);

	KeInitializeEvent(&kEvent, NotificationEvent, FALSE);

	ntStatus = IoSetCompletionRoutineEx(
		UsbPDO,
		irp,
		SyncCompletionRoutine,
		(PVOID)&kEvent,
		TRUE,
		TRUE,
		TRUE);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("\nKeysas - USBFilter!SubmitUrbSync: IoSetCompletionRoutineEx failed.\n");
		goto cleanup;
	}

	ntStatus = IoCallDriver(UsbPDO, irp);

	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject(&kEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL);
	}

	ntStatus = irp->IoStatus.Status;

cleanup:

	if (NULL != irp)
	{
		IoFreeIrp(irp);
		irp = NULL;
	}

	return ntStatus;
}

NTSTATUS
KUFGetUsbConfigurationDescriptor(
	_In_ PDEVICE_OBJECT UsbPDO,
	_In_ USBD_HANDLE UsbHandle,
	_In_ UCHAR Index,
	_Outptr_ PUSB_CONFIGURATION_DESCRIPTOR* UsbConfigDescriptor
)
/*++
Routine Description:
	Request one of the configuration descriptor from the device

Arguments:
	UsbPDO - Pointer to the target USB device Object
	UsbHandle - Handle to the target USB device
	Index - Index of the configuration
	UsbConfigDescriptor - Callee allocated pointer to the configuration descriptor, must be freed by the caller

Return Value:
	STATUS_SUCCESS or error code

IRQL:
	Must be called at PASSIVE_LEVEL
--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	PURB urb = NULL;
	USB_CONFIGURATION_DESCRIPTOR smallConfigDescriptor = { 0 };

	// Validate inputs
	if (NULL == UsbPDO || NULL == UsbHandle || NULL == UsbConfigDescriptor) {
		DbgPrint("\nKeysas - USBFilter!KUFGetUsbConfigurationDescriptor: Invalid inputs\n");
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	// Create URB to get configuration descriptor
	status = USBD_UrbAllocate(UsbHandle, &urb);

	if (!NT_SUCCESS(status) || NULL == urb) {
		DbgPrint("\nKeysas - USBFilter!KUFGetUsbConfigurationDescriptor: Failed to allocate URB for configuration descriptor: %0x\n", status);
		goto cleanup;
	}

	// Format the URB
	UsbBuildGetDescriptorRequest(
		urb,
		sizeof(URB),
		USB_CONFIGURATION_DESCRIPTOR_TYPE,
		Index,
		0,
		&smallConfigDescriptor,
		NULL,
		sizeof(USB_CONFIGURATION_DESCRIPTOR),
		NULL
	);

	// Submit the URB
	status = SubmitUrbSync(UsbPDO, UsbHandle, urb);

	if (!NT_SUCCESS(status) || NULL == urb) {
		DbgPrint("\nKeysas - USBFilter!KUFGetUsbConfigurationDescriptor: Failed to get configuration descriptor: %0x\n", status);
		goto cleanup;
	}

	// Clean URB before next request
	if (NULL != urb) {
		USBD_UrbFree(UsbHandle, urb);
		urb = NULL;
	}

	// Allocate full configuration descriptor based on indicated size
	*UsbConfigDescriptor = (PUSB_CONFIGURATION_DESCRIPTOR)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		smallConfigDescriptor.wTotalLength,
		KEYSAS_USBFILTER_POOL_TAG
	);

	if (NULL == *UsbConfigDescriptor) {
		DbgPrint("\nKeysas - USBFilter!KUFGetUsbConfigurationDescriptor: Failed to allocate memory for configuration descriptor\n");
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	// Create a new URB to get full configuration descriptor
	status = USBD_UrbAllocate(UsbHandle, &urb);

	if (!NT_SUCCESS(status) || NULL == urb) {
		DbgPrint("\nKeysas - USBFilter!KUFGetUsbConfigurationDescriptor: Failed to allocate URB for full configuration descriptor: %0x\n", status);
		goto cleanup;
	}

	// Format the URB
	UsbBuildGetDescriptorRequest(
		urb,
		sizeof(URB),
		USB_CONFIGURATION_DESCRIPTOR_TYPE,
		Index,
		0,
		*UsbConfigDescriptor,
		NULL,
		smallConfigDescriptor.wTotalLength,
		NULL
	);

	// Submit the URB
	status = SubmitUrbSync(UsbPDO, UsbHandle, urb);

	if (!NT_SUCCESS(status) || NULL == urb) {
		DbgPrint("\nKeysas - USBFilter!KUFGetUsbConfigurationDescriptor: Failed to get full configuration descriptor: %0x\n", status);
		goto cleanup;
	}

cleanup:
	if (NULL != urb) {
		USBD_UrbFree(UsbHandle, urb);
		urb = NULL;
	}

	return status;
}

NTSTATUS
KUFGetUsbDeviceDescriptor(
	_In_ PDEVICE_OBJECT UsbPDO,
	_In_ USBD_HANDLE UsbHandle,
	_Out_ PUSB_DEVICE_DESCRIPTOR UsbDeviceDescriptor
)
/*++
Routine Description:
	Request the device descriptor and configuration descriptor for a USB device

Arguments:
	UsbPDO - Pointer to the target USB device Object
	UsbHandle - Handle to the target USB device
	UsbDeviceDescriptor - Caller allocated structure to hold the device descriptor
	UsbConfigDescriptor - Callee allocated pointer to the configuration descriptor, must be freed by the caller

Return Value:
	STATUS_SUCCESS or error code

IRQL:
	Must be called at PASSIVE_LEVEL
--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	PURB urb = NULL;

	// Validate inputs
	if (NULL == UsbPDO || NULL == UsbHandle || NULL == UsbDeviceDescriptor) {
		DbgPrint("\nKeysas - USBFilter!KUFGetUsbDeviceDescriptor: Invalid inputs\n");
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	// Create a URB to request device descriptor
	status = USBD_UrbAllocate(UsbHandle, &urb);

	if (!NT_SUCCESS(status) || NULL == urb) {
		DbgPrint("\nKeysas - USBFilter!KUFGetUsbDeviceDescriptor: Failed to allocate URB for device descriptor: %0x\n", status);
		goto cleanup;
	}

	// Format the URB
	UsbBuildGetDescriptorRequest(
		urb,
		sizeof(URB),
		USB_DEVICE_DESCRIPTOR_TYPE,
		0,
		0,
		UsbDeviceDescriptor,
		NULL,
		sizeof(USB_DEVICE_DESCRIPTOR),
		NULL
	);

	// Submit the URB
	status = SubmitUrbSync(UsbPDO, UsbHandle, urb);

	if (!NT_SUCCESS(status) || NULL == urb) {
		DbgPrint("\nKeysas - USBFilter!KUFGetUsbDeviceDescriptor: Failed to get Device descriptor: %0x\n", status);
		goto cleanup;
	}

cleanup:
	if (NULL != urb) {
		USBD_UrbFree(UsbHandle, urb);
		urb = NULL;
	}

	return status;
}

NTSTATUS
KUFInspectUsbDevice(
	_In_ PDEVICE_OBJECT DriverDevice,
	_In_ PDEVICE_OBJECT TargetDevice
)
/*++
Routine Description:
	Inspect the content of a USB device to filter it

Arguments:
	DriverDevice - Pointer to the instance of the driver
	Device - Pointer to the USB Device PDO targeted

Return Value:
	Returns STATUS_SUCCESS or error code

IRQL:
	Must be called at PASSIVE_LEVEL
--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	USBD_HANDLE usbHandle = NULL;
	USB_DEVICE_DESCRIPTOR usbDeviceDescriptor = { 0 };
	PUSB_CONFIGURATION_DESCRIPTOR usbConfigurationDescriptor = NULL;
	UCHAR index = 0;

	// Validate inputs
	if (NULL == DriverDevice || NULL == TargetDevice) {
		DbgPrint("\nKeysas - USBFilter!KUFInspectUsbDevice: Invalid parameters\n");
		status = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	// TODO -
	// 1. Create function to collect complete USB device descriptor, configurations, interfaces...
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-configuration-descriptors
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-layout
	// 
	// 2. Parse configurations to isolate those with Class 08 (Mass Storage)
	// 
	// 3. Open read pipe and collect first 2MB for checking
	// 
	// 4. Send information for scanning to user space
	// 
	// Create a handle to the target USB device
	status = USBD_CreateHandle(
		DriverDevice,
		TargetDevice,
		USBD_CLIENT_CONTRACT_VERSION_602,
		KEYSAS_USBFILTER_POOL_TAG,
		&usbHandle
	);

	if (!NT_SUCCESS(status) || NULL == usbHandle) {
		DbgPrint("\nKeysas - USBFilter!KUFInspectUsbDevice: Failed to create handle to target USB device: %0x\n", status);
		goto cleanup;
	}

	status = KUFGetUsbDeviceDescriptor(
		TargetDevice,
		usbHandle,
		&usbDeviceDescriptor
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("\nKeysas - USBFilter!KUFInspectUsbDevice: Failed to get device descriptor: %0x\n", status);
		goto cleanup;
	}

	DbgPrint("\nKeysas - USBFilter!KUFInspectUsbDevice: Retrieved descriptor with idVendor: %hu and class: %hhu\n", usbDeviceDescriptor.idVendor, usbDeviceDescriptor.bDeviceClass);
	DbgPrint("\nKeysas - USBFilter!KUFInspectUsbDevice: Retrieved configuration with %hhu configurations\n", usbDeviceDescriptor.bNumConfigurations);

	// Parse all configurations for the device
	for (index = 0; index < usbDeviceDescriptor.bNumConfigurations; index++) {
		status = KUFGetUsbConfigurationDescriptor(
			TargetDevice,
			usbHandle,
			index,
			&usbConfigurationDescriptor
		);

		if (!NT_SUCCESS(status)) {
			DbgPrint("\nKeysas - USBFilter!KUFInspectUsbDevice: Failed to get configuration descriptor %hhu: %0x\n", index, status);
			goto cleanup;
		}

		// Parse configuration descriptor to detect Mass Storage
		if (0x08 == usbDeviceDescriptor.bDeviceClass) {
			DbgPrint("\nKeysas - USBFilter!KUFInspectUsbDevice: Found Mass storage device\n");
		}

		if (NULL != usbConfigurationDescriptor) {
			ExFreePoolWithTag(usbConfigurationDescriptor, KEYSAS_USBFILTER_POOL_TAG);
			usbConfigurationDescriptor = NULL;
		}
	}

cleanup:
	if (NULL != usbHandle) {
		USBD_CloseHandle(usbHandle);
		usbHandle = NULL;
	}

	if (NULL != usbConfigurationDescriptor) {
		ExFreePoolWithTag(usbConfigurationDescriptor, KEYSAS_USBFILTER_POOL_TAG);
		usbConfigurationDescriptor = NULL;
	}

	return status;
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

	DbgPrint("\nKeysas - USBFilter!DriverEntry: Entered\n");

	WDF_DRIVER_CONFIG_INIT(&config, KUFDeviceAddEvt);

	status = WdfDriverCreate(
		DriverObject,
		RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES,
		&config,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("\nKeysas - USBFilter!DriverEntry: WdfDriverCreate failed with status: %0x\n", status);
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
	BOOLEAN isHub = FALSE;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	DbgPrint("\nKeysas - USBFilter!KUFDeviceAddEvt: Entered\n");

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
		DbgPrint("\nKeysas - USBFilter!KUFDeviceAddEvt: WdfDeviceInitAssignWdmIrpPreprocessCallback failed with status: %0x\n", status);
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
		DbgPrint("\nKeysas - USBFilter!KUFDeviceAddEvt: WdfDeviceCreate failed with status: %0x\n", status);
		goto cleanup;
	}

	// Test if it is a USB Hub Device, if not do not attach
	status = KUFIsUsbHub(
		WdfDeviceWdmGetPhysicalDevice(wdfDevice),
		&isHub
	);
	if (!NT_SUCCESS(status)) {
		DbgPrint("\nKeysas - USBFilter!KUFDeviceAddEvt: KUFIsUsbHub failed with status: %0x\n", status);
		goto cleanup;
	}

	if (FALSE == isHub) {
		// Not a hub, do not attach
		DbgPrint("\nKeysas - USBFilter!KUFDeviceAddEvt: Not a Hub, do not attach\n");
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}


	// Give a name to the device so that it can be accessible from userspace
	/*
	if (FALSE == RtlCreateUnicodeString(
		&deviceName,
		L"\\DosDevice\\KeysasUSBFilter"
	)) {
		KdPrintEx((DPFLTR_IHVBUS_ID, DPFLTR_ERROR_LEVEL, "Keysas - USBFilter!KUFDeviceAddEvt: RtlUnicodeStringInit failed with status: %0x\n",
			status));
		DbgPrint("\nKeysas - USBFilter!KUFDeviceAddEvt: RtlUnicodeStringInit failed with status: %0x\n", status);
		goto cleanup;
	}

	status = WdfDeviceCreateSymbolicLink(
		wdfDevice,
		&deviceName
		);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVBUS_ID, DPFLTR_ERROR_LEVEL, "Keysas - USBFilter!KUFDeviceAddEvt: WdfDeviceCreateSymbolicLink failed with status: %0x\n",
			status));
		DbgPrint("\nKeysas - USBFilter!KUFDeviceAddEvt: WdfDeviceCreateSymbolicLink failed with status: %0x\n", status);
		goto cleanup;
	}
	*/

	// Create a queue to handle the requests
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&ioQueueConfig,
		WdfIoQueueDispatchParallel
	);

	ioQueueConfig.EvtIoDeviceControl = KUFEvtDeviceControl;
	ioQueueConfig.PowerManaged = WdfFalse;

	status = WdfIoQueueCreate(
		wdfDevice,
		&ioQueueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("\nKeysas - USBFilter!KUFDeviceAddEvt: WdfIoQueueCreate failed with status: %0x\n", status);
		goto cleanup;
	}

	DbgPrint("\nKeysas - USBFilter!KUFDeviceAddEvt: Success\n");
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

	DbgPrint("\nKeysas - USBFilter!KUFEvtDeviceControl: Entered\n");

	DbgPrint("\nKeysas - USBFilter!KUFEvtDeviceControl: Request 0x%p - IoControlCode 0x%ul\n", Request, IoControlCode);

	WDF_REQUEST_SEND_OPTIONS_INIT(&sendOpts, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

	wdfDevice = WdfIoQueueGetDevice(Queue);

	if (!WdfRequestSend(Request, WdfDeviceGetIoTarget(wdfDevice), &sendOpts)) {
		status = WdfRequestGetStatus(Request);
		WdfRequestComplete(Request, STATUS_SUCCESS);

		DbgPrint("\nKeysas - USBFilter!KUFEvtDeviceControl: WdfRequestSend failed\n");
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
	KIRQL irql = KeGetCurrentIrql();
	PDEVICE_RELATIONS deviceRelations = NULL;
	ULONG i = 0;
	BOOLEAN isMassStorage = FALSE;

	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Device);

	DbgPrint("\nKeysas - USBFilter!KUFDeviceRelationsPostProcessing: Entered\n");
	
	if (Irp->PendingReturned) {
		DbgPrint("\nKeysas - USBFilter!KUFDeviceRelationsPostProcessing: IRP is pending\n");
		IoMarkIrpPending(Irp);

		// Do nothing for now
		goto cleanup;
	}

	// Double check pre-condition, it should OK because the callback is registered only for the correct conditions

	// Check that it is called at PASSIVE_LEVEL, needed to inspect relations
	if (PASSIVE_LEVEL == irql) {
		DbgPrint("\nKeysas - USBFilter!KUFDeviceRelationsPostProcessing: Called at PASSIVE_LEVEL\n");
		// Check that the IRP is successful
		if (STATUS_SUCCESS == Irp->IoStatus.Status) {
			deviceRelations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;
			if (NULL != deviceRelations) {
				for (i = 0; i < deviceRelations->Count; i++) {
					// Get DeviceID
					if (STATUS_SUCCESS == KUFIsUsbMassStorage(deviceRelations->Objects[i], &isMassStorage)) {
						if (isMassStorage) {
							DbgPrint("\nKeysas - USBFilter!KUFDeviceRelationsPostProcessing: Found Mass storage\n");
							//KUFInspectUsbDevice(Device, deviceRelations->Objects[i]);
						}
					}
					KUFInspectUsbDevice(Device, deviceRelations->Objects[i]);
				}
			}
		}
	}
	else {
		DbgPrint("\nKeysas - USBFilter!KUFDeviceRelationsPostProcessing: Called above PASSIVE_LEVEL\n");
	}

cleanup:

	// Resume completion of IRP upward
	return STATUS_CONTINUE_COMPLETION;
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
	Is called at the IRQL of the IRP calling thread.
	For IRP_MN_QUERY_DEVICE_RELATIONS (BusRelations) it should be at IRQL=PASSIVE_LEVEL in context of a system thread
--*/
{
	PIO_STACK_LOCATION irpStack = NULL;

	DbgPrint("\nKeysas - USBFilter!KUFPnpQueryDeviceCallback: Entered\n");
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

		return WdfDeviceWdmDispatchPreprocessedIrp(
			Device,
			Irp
		);
	}
	else {
		// No callback for post processing the IRP
		// Return the IRP to the framework
		IoSkipCurrentIrpStackLocation(Irp);

		return WdfDeviceWdmDispatchPreprocessedIrp(
			Device,
			Irp
		);
	}
}
use std::mem::size_of;

use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{STATUS_SUCCESS, BOOLEAN};
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage, FILTER_MESSAGE_HEADER,
    FILTER_REPLY_HEADER,
};

#[derive(Debug)]
#[repr(C)]
struct DriverMessage {
    header: FILTER_MESSAGE_HEADER,
    content: [u8; 1024],
}

#[derive(Debug)]
#[repr(C)]
struct UserReply {
    header: FILTER_REPLY_HEADER,
    file_safe: BOOLEAN,
}

fn main() {
    // Open communication canal with the driver
    let com_port_name = U16CString::from_str("\\KeysasPort").unwrap().into_raw();

    let handle;

    unsafe {
        handle = FilterConnectCommunicationPort(
            PCWSTR(com_port_name),
            0,
            None,
            0,
            None).unwrap();
    }

    // Listen for messages from the driver
    loop {
        let mut message = DriverMessage {
            header: FILTER_MESSAGE_HEADER::default(),
            content: [0; 1024],
        };

        unsafe {
            FilterGetMessage(
                handle,
                &mut message.header,
                u32::try_from(size_of::<DriverMessage>()).unwrap(),
                None,
            )
            .unwrap();
        }

        println!("{:?}", message);

        let mut reply = UserReply {
            header: FILTER_REPLY_HEADER::default(),
            file_safe: BOOLEAN::from(true),
        };

        reply.header.MessageId = message.header.MessageId;
        reply.header.Status = STATUS_SUCCESS;

        unsafe {
            FilterReplyMessage(
                handle,
                &reply.header,
                u32::try_from(size_of::<FILTER_REPLY_HEADER>()).unwrap()
                    + u32::try_from(size_of::<BOOLEAN>()).unwrap(),
            )
            .unwrap();
        }
    }
}

#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

mod vmlinux;

use aya_bpf::{
    macros::{lsm, map},
    programs::LsmContext,
    cty::{c_char, c_long},
    helpers::bpf_d_path,
    maps::PerCpuArray,
    bindings::path
};
use aya_log_ebpf::info;

use vmlinux::{file, vfsmount, super_block, dentry};

const PATH_LENGTH: usize = 64;

#[derive(Copy, Clone)]
#[repr(C)]
struct Path {
    path: [u8; PATH_LENGTH]
}

#[map]
static mut PATH_BUF: PerCpuArray<Path> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn get_bpf_d_path(path: *mut path, buf: &mut [u8]) -> Result<usize, c_long> {
    let ret = unsafe {
        bpf_d_path(
            path,
            buf.as_mut_ptr() as *mut c_char,
            buf.len() as u32
        )
    };

    if ret < 0 {
        return Err(ret);
    }

    Ok(ret as usize)
}

// unsafe fn get_mount_point(path: *mut path, buf: &mut [u8]) -> Result<usize, c_long> {
//     let mp: *mut vfsmount = (*path).mnt;
//     //let sb: *mut super_block = (*mp).mnt_sb;
//     let mr: *mut dentry = (*mp).mnt_root;

//     let mut lgth: usize = 0;

//     loop {
//         //buf[lgth] = (*sb).s_id[lgth] as u8;
//         buf[lgth] = (*mr).d_iname[lgth] as u8;
//         lgth += 1;

//         if lgth == 32 {
//             buf[lgth] = 0;
//             break;
//         }
//         //if (*sb).s_id[lgth] == 0 {
//         if (*mr).d_iname[lgth] == 0 {
//             break;
//         }
//     } 

//     Ok(lgth)
// }

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        match try_file_open(ctx) {
            Ok(ret) => ret,
            Err(ret) => ret,
        }
    }
}

unsafe fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let buf = unsafe {
        let buf_ptr = PATH_BUF.get_ptr_mut(0).ok_or(0)?;
        &mut *buf_ptr
    };

    let f: *const file = ctx.arg(0);
    let p = &(*f).f_path as *const _ as *mut path;
    let len = get_bpf_d_path(p, &mut buf.path).map_err(|_| 0)?;
    // let len = unsafe {
    //     get_mount_point(p, &mut buf.path).map_err(|_| 0)?
    // };
    if len >= PATH_LENGTH {
        return Err(0);
    }
    // let p_str = match core::str::from_utf8(&buf.path[..len]) {
    //     Ok(s) => s,
    //     Err(_) => {
    //         info!(&ctx, "Failed to get file path");
    //         return Err(0);
    //     }
    // };
    let p_str = core::str::from_utf8_unchecked(&buf.path[..len]);

    //if p_str.starts_with("/media/lbo") {
        info!(&ctx,
            "File open called for {}",
            p_str
        );
    //}
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
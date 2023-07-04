// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-transit".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * This file contains various funtions
 * to sandbox this binary using seccomp.
 */
pub use anyhow::Result;

#[cfg(target_os = "linux")]
use syscallz::{Context, Syscall};

#[cfg(not(tarpaulin_include))]
#[cfg(target_os = "linux")]
pub fn init() -> Result<()> {
    let mut ctx = Context::init()?;
    ctx.allow_syscall(Syscall::sendto)?;
    ctx.allow_syscall(Syscall::read)?;
    ctx.allow_syscall(Syscall::fsync)?;
    ctx.allow_syscall(Syscall::write)?;
    ctx.allow_syscall(Syscall::connect)?;
    ctx.allow_syscall(Syscall::close)?;
    ctx.allow_syscall(Syscall::clock_nanosleep)?;
    ctx.allow_syscall(Syscall::rt_sigaction)?;
    ctx.allow_syscall(Syscall::recvfrom)?;
    ctx.allow_syscall(Syscall::munmap)?;
    ctx.allow_syscall(Syscall::recvmsg)?;
    ctx.allow_syscall(Syscall::lseek)?;
    ctx.allow_syscall(Syscall::socket)?;
    ctx.allow_syscall(Syscall::mmap)?;
    ctx.allow_syscall(Syscall::sendmsg)?;
    ctx.allow_syscall(Syscall::statx)?;
    ctx.allow_syscall(Syscall::rt_sigprocmask)?;
    ctx.allow_syscall(Syscall::dup2)?;
    ctx.allow_syscall(Syscall::newfstatat)?;
    ctx.allow_syscall(Syscall::madvise)?;
    ctx.allow_syscall(Syscall::accept4)?;
    ctx.allow_syscall(Syscall::bind)?;
    ctx.allow_syscall(Syscall::listen)?;
    ctx.allow_syscall(Syscall::mremap)?;
    ctx.allow_syscall(Syscall::brk)?;
    ctx.allow_syscall(Syscall::poll)?;
    ctx.allow_syscall(Syscall::mprotect)?;
    ctx.allow_syscall(Syscall::ioctl)?;
    ctx.allow_syscall(Syscall::pread64)?;
    ctx.allow_syscall(Syscall::access)?;
    ctx.allow_syscall(Syscall::execve)?;
    ctx.allow_syscall(Syscall::sigaltstack)?;
    ctx.allow_syscall(Syscall::prctl)?;
    ctx.allow_syscall(Syscall::arch_prctl)?;
    ctx.allow_syscall(Syscall::futex)?;
    ctx.allow_syscall(Syscall::sched_getaffinity)?;
    ctx.allow_syscall(Syscall::set_tid_address)?;
    ctx.allow_syscall(Syscall::openat)?;
    ctx.allow_syscall(Syscall::set_robust_list)?;
    ctx.allow_syscall(Syscall::prlimit64)?;
    ctx.allow_syscall(Syscall::getrandom)?;
    ctx.allow_syscall(Syscall::rseq)?;
    ctx.allow_syscall(Syscall::landlock_create_ruleset)?;
    ctx.allow_syscall(Syscall::landlock_add_rule)?;
    ctx.allow_syscall(Syscall::landlock_restrict_self)?;
    ctx.load()?;
    Ok(())
}

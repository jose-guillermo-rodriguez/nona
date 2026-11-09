// BINARY: nona_enclave - AWS Nitro Confidential Enclave AF_VSOCK & AF_UNIX Daemon

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(not(feature = "std"))]
#[link(name = "c")]
extern "C" {}

// Fallback loop for non-POSIX bare-metal compilation checks
#[cfg(all(not(feature = "std"), target_os = "none"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(all(not(feature = "std"), target_os = "none"))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(all(not(feature = "std"), not(target_os = "none")))]
#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    let port = nona_core::enclave_server::DEFAULT_VSOCK_PORT;
    let unix_sock = nona_core::enclave_server::DEFAULT_UNIX_SOCKET;
    unsafe { nona_core::enclave_server::run_dual_server(port, unix_sock) }
}

#[cfg(feature = "std")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut unix_only = false;
    let mut custom_unix = None;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--mock-unix" || args[i] == "--unix" {
            unix_only = true;
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                custom_unix = Some(args[i + 1].clone());
                i += 1;
            }
        }
        i += 1;
    }

    if std::env::var("NONA_MOCK_UNIX").is_ok() {
        unix_only = true;
    }

    if unix_only {
        let path = custom_unix.unwrap_or_else(|| "/tmp/nona.sock".to_string());
        let mut path_bytes = path.into_bytes();
        path_bytes.push(0);
        unsafe {
            nona_core::enclave_server::run_unix_server(&path_bytes);
        }
        return;
    }

    let port = nona_core::enclave_server::DEFAULT_VSOCK_PORT;
    let unix_sock = nona_core::enclave_server::DEFAULT_UNIX_SOCKET;
    unsafe {
        nona_core::enclave_server::run_dual_server(port, unix_sock);
    }
}

// Canonical Linux x86-64 ELF entry point for standalone bare-metal execution
#[cfg(all(not(feature = "std"), target_os = "none", target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    let ret = main(0, core::ptr::null());
    core::arch::asm!(
        "mov eax, 231", // SYS_exit_group
        "mov edi, {0:e}",
        "syscall",
        in(reg) ret,
        options(noreturn)
    );
}

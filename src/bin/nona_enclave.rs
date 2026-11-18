//! AWS Nitro Confidential Enclave daemon entrypoint.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(not(feature = "std"))]
#[link(name = "c")]
extern "C" {}

#[cfg(all(not(feature = "std"), target_os = "none"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    nona_core::exception::zeroize_and_abort(-99);
}

#[cfg(all(not(feature = "std"), not(target_os = "none")))]
#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    const _: () = {
        assert!(
            nona_core::enclave_server::MAX_VSOCK_FRAME_BYTES
                > nona_core::enclave_server::MAX_WIRE_PAYLOAD_BYTES
        );
    };
    nona_core::enclave_server::harden_enclave_process();
    let port = nona_core::enclave_server::DEFAULT_VSOCK_PORT;
    let status = unsafe { nona_core::enclave_server::run_vsock_server(port) };
    if status != 0 {
        nona_core::exception::zeroize_and_abort(status);
    }
    0
}

#[cfg(feature = "std")]
fn main() {
    use nona_core::enclave_server::{MAX_VSOCK_FRAME_BYTES, MAX_WIRE_PAYLOAD_BYTES};

    const MAX_DAEMON_CLI_ARGS: usize = 16;
    const MAX_SOCKET_PATH_BYTES: usize = 107;
    const _: () = {
        assert!(MAX_VSOCK_FRAME_BYTES > MAX_WIRE_PAYLOAD_BYTES);
    };

    nona_core::enclave_server::harden_enclave_process();
    let args: Vec<String> = std::env::args().take(MAX_DAEMON_CLI_ARGS).collect();
    let mut unix_only = false;
    let mut custom_unix = None;

    let mut i = 1usize;
    while i < args.len() {
        if args[i] == "--mock-unix" || args[i] == "--unix" {
            unix_only = true;
            if let Some(next_idx) = i.checked_add(1) {
                if next_idx < args.len() && !args[next_idx].starts_with("--") {
                    if args[next_idx].len() > MAX_SOCKET_PATH_BYTES {
                        nona_core::exception::zeroize_and_abort(
                            nona_core::gatekeeper::NONA_ERR_LENGTH_BOUND_VIOLATION,
                        );
                    }
                    custom_unix = Some(args[next_idx].clone());
                    i = next_idx;
                }
            }
        }
        let Some(next_i) = i.checked_add(1) else {
            break;
        };
        i = next_i;
    }

    if std::env::var("NONA_MOCK_UNIX").is_ok() {
        unix_only = true;
    }

    if unix_only {
        let path = custom_unix.unwrap_or_else(|| "/tmp/nona.sock".to_string());
        if path.len() > MAX_SOCKET_PATH_BYTES {
            nona_core::exception::zeroize_and_abort(
                nona_core::gatekeeper::NONA_ERR_LENGTH_BOUND_VIOLATION,
            );
        }
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

#[cfg(all(not(feature = "std"), target_os = "none"))]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    nona_core::exception::zeroize_and_abort(nona_core::gatekeeper::NONA_ERR_INTERNAL_PANIC);
}

#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    if user::run_restricted_self_test() {
        user::process_exit(0);
    } else {
        user::process_exit(1);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    user::process_exit(1)
}

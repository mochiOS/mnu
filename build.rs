fn main() {
    match std::env::var("CARGO_CFG_TARGET_OS") {
        Ok(value) if value == "none" => {}
        Ok(_) => {
            eprintln!("this target isnt supported");
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("CARGO_CFG_TARGET_OS not set: {}", error);
            std::process::exit(0);
        }
    }

    if std::env::var_os("CARGO_CFG_TEST").is_some() {
        eprintln!(
            "cargo test is disabled for this crate; use the kernel/QEMU self-test path instead"
        );
        std::process::exit(0);
    }

    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("CARGO_MANIFEST_DIR not set: {}", error);
            std::process::exit(0);
        }
    };
    println!("cargo:rustc-link-arg=-T{}/kernel.ld", manifest_dir);
    println!("cargo:rerun-if-changed=kernel.ld");
}

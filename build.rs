use std::fs;
use std::path::Path;
use std::process::Command;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    // Try to find bpf-linker using which command
    if let Ok(output) = Command::new("which").arg("bpf-linker").output() {
        if output.status.success() {
            let bpf_linker_path = String::from_utf8_lossy(&output.stdout);
            let bpf_linker_path = bpf_linker_path.trim();
            println!("cargo:rerun-if-changed={}", bpf_linker_path);
        }
    }

    // Fallback: tell cargo to rerun if PATH changes
    println!("cargo:rerun-if-env-changed=PATH");

    // Post-build: Copy the generated .so file to a .o file for eBPF loading
    if let Ok(profile) = std::env::var("PROFILE") {
        let target_dir = format!("target/bpfel-unknown-none/{}", profile);
        let so_path = format!("{}/libnetshield_ebpf.so", target_dir);
        let o_path = format!("{}/netshield_xdp.o", target_dir);

        if Path::new(&so_path).exists() {
            if let Err(e) = fs::copy(&so_path, &o_path) {
                println!("cargo:warning=Failed to copy eBPF object: {}", e);
            } else {
                println!("cargo:warning=eBPF object created: {}", o_path);
            }
        }
    }
}

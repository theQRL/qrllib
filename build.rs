// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use bindgen;
use cc;
use cmake::Config;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    Command::new("git")
        .arg("submodule")
        .arg("update")
        .arg("--init")
        .arg("--recursive")
        .status()
        .unwrap();

    let kyber_ref_path = Path::new("deps/kyber/ref/filler");
    //let kyber_wrapper_path = Path::new("src/rustwrapper/kyber/kyber_wrapper.c");
    cc::Build::new()
        .define("KYBER_K", "3")
        .include(kyber_ref_path.with_file_name(""))
        .flag("-g")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-O3")
        .flag("-fomit-frame-pointer")
        .flag("-fPIC")
        .file(kyber_ref_path.with_file_name("randombytes.c"))
        .file(kyber_ref_path.with_file_name("kem.c"))
        .file(kyber_ref_path.with_file_name("poly.c"))
        .file(kyber_ref_path.with_file_name("polyvec.c"))
        .file(kyber_ref_path.with_file_name("reduce.c"))
        .file(kyber_ref_path.with_file_name("cbd.c"))
        .file(kyber_ref_path.with_file_name("precomp.c"))
        .file(kyber_ref_path.with_file_name("ntt.c"))
        .file(kyber_ref_path.with_file_name("verify.c"))
        .file(kyber_ref_path.with_file_name("indcpa.c"))
        .file(kyber_ref_path.with_file_name("kex.c"))
        .file(kyber_ref_path.with_file_name("fips202.c"))
        //.file(kyber_wrapper_path)
        .static_flag(true)
        .compile("kyber");

    let dilithium_ref_path = Path::new("deps/dilithium/ref/filler");
    //let dilithium_wrapper_path = Path::new("src/rustwrapper/dilithium/dilithium_wrapper.c");
    cc::Build::new()
        .include(dilithium_ref_path.with_file_name(""))
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-O3")
        .flag("-fomit-frame-pointer")
        .file(dilithium_ref_path.with_file_name("randombytes.c"))
        .file(dilithium_ref_path.with_file_name("sign.c"))
        .file(dilithium_ref_path.with_file_name("poly.c"))
        .file(dilithium_ref_path.with_file_name("polyvec.c"))
        .file(dilithium_ref_path.with_file_name("packing.c"))
        .file(dilithium_ref_path.with_file_name("reduce.c"))
        .file(dilithium_ref_path.with_file_name("ntt.c"))
        .file(dilithium_ref_path.with_file_name("rounding.c"))
        .file(dilithium_ref_path.with_file_name("fips202.c"))
        //.file(dilithium_wrapper_path)
        .static_flag(true)
        .compile("dilithium");

    // Builds the project, installing it into $OUT_DIR
    // let mut dst = Config::new("")
    //     .define("CMAKE_C_COMPILER", "gcc")
    //     .define("CMAKE_CXX_COMPILER", "g++")
    //     .build();

    // dst.push("build");
    // println!("cargo:rustc-link-search=native={}", dst.display());
    // println!("cargo:rustc-link-lib=static=kyber");
    // println!("cargo:rustc-link-lib=static=dilithium");
    // println!("cargo:rerun-if-changed=build.rs");
    // let kyber_wrapper_path: PathBuf = [r"src", "rustwrapper", "kyber_wrapper.hxx"]
    //     .iter()
    //     .collect();
    // println!(
    //     "cargo:rerun-if-changed={}",
    //     kyber_wrapper_path.to_str().unwrap()
    // );
    // let dilithium_wrapper_path: PathBuf = [r"src", "rustwrapper", "dilithium_wrapper.hxx"]
    //     .iter()
    //     .collect();
    // println!(
    //     "cargo:rerun-if-changed={}",
    //     dilithium_wrapper_path.to_str().unwrap()
    // );

    // //Write the bindings to the $OUT_DIR/bindings.rs file.
    // let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // let dependencies_path = PathBuf::from("deps");

    // let dilithium_bindings = bindgen::Builder::default()
    //     // The input header we would like to generate
    //     // bindings for.
    //     .header(dilithium_wrapper_path.to_str().unwrap())
    //     .allowlist_var("CRYPTO_.*")
    //     //.allowlist_function("crypto_sign.*")
    //     //.allowlist_function("randombytes")
    //     .clang_arg(format!("-I{}", dependencies_path.to_str().unwrap()))
    //     .clang_arg("-x")
    //     .clang_arg("c++")
    //     // Tell cargo to invalidate the built crate whenever any of the
    //     // included header files changed.
    //     .parse_callbacks(Box::new(bindgen::CargoCallbacks))
    //     // Finish the builder and generate the bindings.
    //     .generate()
    //     // Unwrap the Result and panic on failure.
    //     .expect("Unable to generate bindings");
    // dilithium_bindings
    //     .write_to_file(out_path.join("dilithium_bindings.rs"))
    //     .expect("Couldn't write bindings!");

    // // The bindgen::Builder is the main entry point
    // // to bindgen, and lets you build up options for
    // // the resulting bindings.
    // let kyber_bindings = bindgen::Builder::default()
    //     // The input header we would like to generate
    //     // bindings for.
    //     .header(kyber_wrapper_path.to_str().unwrap())
    //     .allowlist_var("KYBER_.*")
    //     //.allowlist_function("crypto_kem.*")
    //     .clang_arg(format!("-I{}", dependencies_path.to_str().unwrap()))
    //     .clang_arg("-x")
    //     .clang_arg("c++")
    //     // Tell cargo to invalidate the built crate whenever any of the
    //     // included header files changed.
    //     .parse_callbacks(Box::new(bindgen::CargoCallbacks))
    //     // Finish the builder and generate the bindings.
    //     .generate()
    //     // Unwrap the Result and panic on failure.
    //     .expect("Unable to generate bindings");
    // kyber_bindings
    //     .write_to_file(out_path.join("kyber_bindings.rs"))
    //     .expect("Couldn't write bindings!");
}

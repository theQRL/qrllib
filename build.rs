// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use bindgen;
use cmake::Config;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    Command::new("git")
        .arg("submodule")
        .arg("update")
        .arg("--init")
        .arg("--recursive")
        .status()
        .unwrap();

    // Builds the project, installing it into $OUT_DIR
    let mut dst = Config::new("")
        .define("CMAKE_C_COMPILER", "gcc")
        .define("CMAKE_CXX_COMPILER", "g++")
        .build();

    dst.push("build");
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=static=kyber");
    println!("cargo:rerun-if-changed=build.rs");
    let wrapper_path: PathBuf = [r"src", "rustwrapper", "wrapper.hxx"].iter().collect();
    println!("cargo:rerun-if-changed={}", wrapper_path.to_str().unwrap());

    let dependencies_path = PathBuf::from("deps");
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    // TODO: allowlist functions and types to reduce bindings size
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(wrapper_path.to_str().unwrap())
        .clang_arg(format!("-I{}", dependencies_path.to_str().unwrap()))
        .clang_arg("-x")
        .clang_arg("c++")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    //Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

use std::process::Command;
use std::path::PathBuf;
use std::env;
use cmake::Config;
use bindgen;

fn main() {
    Command::new("git").arg("submodule")
                        .arg("update")
                        .arg("--init")
                        .arg("--recursive")
                       .status().unwrap();

    // Builds the project in the directory located in `libfoo`, installing it
    // into $OUT_DIR
    let mut dst = Config::new("./")
                 .define("CMAKE_C_COMPILER", "gcc")
                 .define("CMAKE_CXX_COMPILER", "g++")
                 .build();

    dst.push("build");
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=static=kyber");
    println!("cargo:rerun-if-changed=./src/rustwrapper/wrapper.hxx");

    // // The bindgen::Builder is the main entry point
    // // to bindgen, and lets you build up options for
    // // the resulting bindings.
    // let bindings = bindgen::Builder::default()
    //     // The input header we would like to generate
    //     // bindings for.
    //     .header("./src/rustwrapper/wrapper.hxx")
    //     .clang_arg("-I./deps/")
    //     .allowlist_type("Kyber")
    //     .allowlist_function("Kyber_.*")
    //     // Tell cargo to invalidate the built crate whenever any of the
    //     // included header files changed.
    //     .parse_callbacks(Box::new(bindgen::CargoCallbacks))
    //     // Finish the builder and generate the bindings.
    //     .generate()
    //     // Unwrap the Result and panic on failure.
    //     .expect("Unable to generate bindings");

    // let path = std::path::PathBuf::from("src/"); // include path
    // let path2 = std::path::PathBuf::from("deps/");
    // let mut b = autocxx_build::Builder::new("src/lib.rs", &[&path2, &path])
    //     .expect_build();
    // // This assumes all your C++ bindings are in main.rs
    // b.flag_if_supported("-std=c++14").compile("stuff");
    // println!("cargo:rerun-if-changed=src/lib.rs");

    cxx_build::bridge("src/lib.rs")
        .include("deps/")
        .file("src/kyber/kyber.cpp")
        .flag_if_supported("-std=c++11")
        .compile("kyber");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    //let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // bindings
    //     .write_to_file(out_path.join("bindings.rs"))
    //     .expect("Couldn't write bindings!");
}

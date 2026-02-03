use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use bundled protoc from protobuf-src
    // SAFETY: This is run at build time in a single-threaded build script context.
    // No other threads are reading environment variables concurrently.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("PROTOC", protobuf_src::protoc());
    }

    let proto_files = [
        "../../proto/navigator.proto",
        "../../proto/datamodel.proto",
        "../../proto/test.proto",
    ];
    let out_dir = PathBuf::from("src/proto");

    // Ensure the output directory exists
    std::fs::create_dir_all(&out_dir)?;

    // Configure tonic-build
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&out_dir)
        .compile_protos(&proto_files, &["../../proto"])?;

    // Tell cargo to rerun if the proto file changes
    for proto_file in proto_files {
        println!("cargo:rerun-if-changed={proto_file}");
    }

    Ok(())
}

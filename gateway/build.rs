fn main() -> Result<(), Box<dyn std::error::Error>> {
    // M1: validate proto→Rust codegen only. Service (client/server) generation
    // is enabled in M4 when the gateway calls the control plane over gRPC.
    println!("cargo:rerun-if-changed=../proto/jumpgate/health/v1/health.proto");
    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .compile_protos(&["../proto/jumpgate/health/v1/health.proto"], &["../proto"])?;
    Ok(())
}

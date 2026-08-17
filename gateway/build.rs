fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .compile_protos(&["../proto/jumpgate/health/v1/health.proto"], &["../proto"])?;
    Ok(())
}

use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // M4: the gateway calls the control plane over gRPC, so client stubs are
    // generated. Server generation remains off until the gateway hosts services.
    //
    // The session proto imports buf/validate/validate.proto (a remote buf module
    // dep). Vanilla protoc can't resolve buf's remote deps, so we materialize the
    // full proto closure (our files + deps) into OUT_DIR via `buf export` and point
    // protoc's include path there. `buf` is provided by the Nix devshell.
    println!("cargo:rerun-if-changed=../proto/jumpgate/health/v1/health.proto");
    println!("cargo:rerun-if-changed=../proto/jumpgate/session/v1/session.proto");
    println!("cargo:rerun-if-changed=../proto/jumpgate/dataplane/v1/dataplane.proto");
    println!("cargo:rerun-if-changed=../proto/buf.yaml");
    println!("cargo:rerun-if-changed=../buf.yaml");
    println!("cargo:rerun-if-changed=../buf.lock");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let export_dir = out_dir.join("proto_export");
    let status = Command::new("buf")
        .args(["export", "../proto", "--output"])
        .arg(&export_dir)
        .status()?;
    if !status.success() {
        return Err(format!("buf export failed with status {status}").into());
    }

    let health = export_dir.join("jumpgate/health/v1/health.proto");
    let session = export_dir.join("jumpgate/session/v1/session.proto");
    let dataplane = export_dir.join("jumpgate/dataplane/v1/dataplane.proto");
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&[health, session, dataplane], &[export_dir])?;
    Ok(())
}

{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    go-overlay = {
      url = "github:purpleclay/go-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, go-overlay, git-hooks, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ go-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };

        go = pkgs.go-bin.fromGoMod ./warden/go.mod;

        # S3-compatible object store used by the recording pipeline in local dev
        # and the end-to-end tests. Installed from the upstream release archive
        # (not yet packaged in nixpkgs).
        silo =
          let
            release = "RELEASE.2026-08-06T00-00-00Z";
            ver = "20260806000000.0.0";
            src =
              if pkgs.stdenv.hostPlatform.system == "x86_64-linux" then
                pkgs.fetchurl {
                  url = "https://github.com/pgsty/silo/releases/download/${release}/silo_${ver}_linux_amd64.tar.gz";
                  sha256 = "d63d57cc7f0535e1aa116f9e5f42117dbfc4f63492da692b64d3ba6ded30e574";
                }
              else if pkgs.stdenv.hostPlatform.system == "aarch64-linux" then
                pkgs.fetchurl {
                  url = "https://github.com/pgsty/silo/releases/download/${release}/silo_${ver}_linux_arm64.tar.gz";
                  sha256 = "4389413672d8b2681130a2e518ae6609406671e0f0a5d34934c20701078ee1ad";
                }
              else throw "silo: unsupported system ${pkgs.stdenv.hostPlatform.system}";
          in
          pkgs.stdenv.mkDerivation {
            pname = "silo";
            version = ver;
            inherit src;
            sourceRoot = ".";
            nativeBuildInputs = [ pkgs.autoPatchelfHook ];
            installPhase = ''
              runHook preInstall
              install -Dm755 silo $out/bin/silo
              runHook postInstall
            '';
          };

        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            gofmt.enable = true;
            golangci-lint.enable = true;
            rustfmt-rustup = {
              enable = true;
              name = "rustfmt (rustup)";
              entry = "cargo fmt --all -- --check";
              language = "system";
              pass_filenames = false;
              files = "\\.rs$";
            };
            clippy-rustup = {
              enable = true;
              name = "clippy (rustup)";
              entry = "cargo clippy --all-targets -- -D warnings";
              language = "system";
              pass_filenames = false;
              files = "\\.rs$";
            };
          };
        };
      in
      {
        devShells.default = pkgs.mkShell {
          # Run the git-hooks installer, then ensure the wasm target is present
          # (rustup-managed) so `wasm-pack build` / `make wasm` works out of the box.
          shellHook = pre-commit-check.shellHook + ''
            rustup target add wasm32-unknown-unknown 2>/dev/null || true
          '';

          buildInputs = [
            go.withDefaultTools
            pkgs.golangci-lint
            pkgs.sqlc
            pkgs.goose
            pkgs.rustup
            pkgs.wasm-pack
            pkgs.cargo-nextest
            pkgs.cargo-watch
            pkgs.cargo-deny
            pkgs.buf
            pkgs.protobuf
            pkgs.protoc-gen-go
            pkgs.protoc-gen-go-grpc
            pkgs.protoc-gen-connect-go
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.postgresql
            pkgs.openfga
            pkgs.minio-client
            silo
            pkgs.kubernetes-helm
            pkgs.kubectl
            pkgs.kind
            pkgs.gnumake
            pkgs.chromium
            pkgs.process-compose
            pkgs.air
          ];

          RUST_BACKTRACE = 1;
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD =
            pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux "1";
          PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH =
            pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux "${pkgs.chromium}/bin/chromium";
        };
      });
}

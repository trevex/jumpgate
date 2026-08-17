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

        go = pkgs.go-bin.fromGoMod ./control-plane/go.mod;

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
          inherit (pre-commit-check) shellHook;

          buildInputs = [
            go.withDefaultTools
            pkgs.golangci-lint
            pkgs.sqlc
            pkgs.goose
            pkgs.rustup
            pkgs.cargo-nextest
            pkgs.cargo-watch
            pkgs.buf
            pkgs.protobuf
            pkgs.protoc-gen-go
            pkgs.protoc-gen-go-grpc
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.postgresql
            pkgs.openfga
            pkgs.minio-client
            pkgs.kubernetes-helm
            pkgs.kubectl
            pkgs.kind
            pkgs.gnumake
          ];

          RUST_BACKTRACE = 1;
          PROTOC = "${pkgs.protobuf}/bin/protoc";
        };
      });
}

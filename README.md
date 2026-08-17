# jumpgate

Enterprise Privileged Access Management (PAM) — agentless, JIT-first.
Go control plane + Rust data plane.

## Development

Requires [Nix](https://nixos.org/download) (flakes enabled) and [direnv](https://direnv.net).

````sh
direnv allow      # or: nix develop
make gen          # generate protobuf stubs
make build        # build all binaries
make test         # run Go + Rust tests
````

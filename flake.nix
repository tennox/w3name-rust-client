{
  description = "w3name-rust-client - A tool for creating verifiable names in a web3 world";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05"; # or use /nixos-unstable to get latest packages, but maybe less caching
    systems.url = "github:nix-systems/default"; # (i) allows overriding systems easily, see https://github.com/nix-systems/nix-systems#consumer-usage
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay"; # TODO: replace with fenix?
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = inputs@{ self, systems, flake-parts, nixpkgs, rust-overlay, crane, devenv, ... }: (
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = (import systems);
      imports = [
        inputs.devenv.flakeModule
      ];

      # perSystem docs: https://flake.parts/module-arguments.html#persystem-module-parameters
      perSystem = { config, self', inputs', pkgs, system, ... }: (
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              rust-overlay.overlays.default
            ];
          };
          # docs: https://github.com/oxalica/rust-overlay?tab=readme-ov-file#cheat-sheet-common-usage-of-rust-bin
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            targets = [
              "x86_64-unknown-linux-musl"
              # "wasm-unknown-unknown"
            ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          commonArgs = {
            # https://crane.dev/getting-started.html
            src = craneLib.path ./.;
            # CARGO_BUILD_TARGET = "wasm-unknown-unknown";
            # CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            # CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
            # Add native deps needed to build openssl and compile protobufs
            nativeBuildInputs = with pkgs; [ protobuf perl cmake pkg-config ];
            buildInputs = with pkgs; [ openssl ];
          };
          my-crate = craneLib.buildPackage (commonArgs // {
            pname = "w3name";
            version = "0.1.8";
            # Keep original cargo build options for compatibility
            cargoExtraArgs = "--no-default-features";
            doCheck = false; # Skip tests for now due to TTL precision issue
          });
        in
        {
          _module.args.pkgs = pkgs; # apply overlay - https://flake.parts/overlays#consuming-an-overlay
          # Per-system attributes can be defined here. The self' and inputs'
          # module parameters provide easy access to attributes of the same
          # system.
          checks = {
            inherit my-crate;
          };

          packages.default = my-crate;

          devenv.shells.default = {
            imports = [
              ./devenv.nix
            ];
            languages.rust.toolchain = rustToolchain;
            # Useful packages for nix, so I put them here instead of devenv.nix
            packages = with pkgs; [
              nixpkgs-fmt
              nil
              # Keep original dev tools
              pre-commit
              rust-analyzer
              bacon
              clippy
            ];
          };
        }
      );
      flake = {
        # The usual flake attributes can be defined here, including system-
        # agnostic ones like nixosModule and system-enumerating ones, although
        # those are more easily expressed in perSystem.

      };
    }
  );

  nixConfig = {
    extra-substituters = [
      "https://devenv.cachix.org" # https://devenv.sh/binary-caching/
      "https://nix-community.cachix.org" # for fenix
    ];
    extra-trusted-public-keys = [
      "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
    ];
  };
}

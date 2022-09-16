{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };

        # native deps needed to build libp2p-core
        native-deps = with pkgs; [ openssl.dev protobuf ];
      in
      {
        defaultPackage = naersk-lib.buildPackage {
          src = ./.;

          nativeBuildInputs = native-deps;
        };

        defaultApp = utils.lib.mkApp {
          drv = self.defaultPackage."${system}";
        };

        devShell = with pkgs; mkShell {
          buildInputs = [ cargo rustc rustfmt pre-commit rustPackages.clippy ] ++ native-deps;
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      });
}

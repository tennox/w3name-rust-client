{
  description = "w3name - A utility for managing IPNS names";

  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    systems.url = "github:nix-systems/default"; # (i) allows overriding systems easily
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs@{ self, nixpkgs, utils, naersk, systems, devenv, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = (import systems);
      imports = [
        inputs.devenv.flakeModule
      ];

      # perSystem docs: https://flake.parts/module-arguments.html#persystem-module-parameters
      perSystem = { config, self', inputs', pkgs, system, ... }:
        let
          naersk-lib = pkgs.callPackage naersk { };
          
          # native deps needed to build openssl and compile protobufs
          native-deps = with pkgs; [ protobuf perl cmake ];

          w3name-package = naersk-lib.buildPackage {
            src = ./.;
            nativeBuildInputs = native-deps;
            cargoBuildOptions = opts: opts ++ ["--no-default-features"];
          };
        in
        {
          packages.default = w3name-package;
          
          apps.default = utils.lib.mkApp {
            drv = w3name-package;
          };

          devenv.shells.default = {
            name = "w3name";
            
            imports = [
              ./devenv.nix
            ];
            
            # Useful packages for nix, so I put them here instead of devenv.nix
            packages = with pkgs; [
              nixpkgs-fmt
              nil
            ] ++ native-deps;
          };
        };

      flake = {
        # The usual flake attributes can be defined here, including system-
        # agnostic ones like nixosModule and system-enumerating ones, although
        # those are more easily expressed in perSystem.
      };
    };

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

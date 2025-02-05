{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem
    (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
        with pkgs; {
          devShells = {
            default = mkShell {
              buildInputs = [clang-tools_15 libbpf clang_15 llvm_15 bpftools bear];
              nativeBuildInputs = [linuxHeaders];
              hardeningDisable = ["all"];
              NIX_CFLAGS_COMPILE = ["-Wno-unused-command-line-argument"];
            };

            testing = mkShell {
              buildInputs = [skaffold kubectl kind ko kubernetes-helm git];

              shellHook = ''
                alias k=kubectl
              '';
            };
          };
        }
    );
}

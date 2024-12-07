{pkgs ? import <nixpkgs> {}}:
with pkgs;
  mkShell {
    buildInputs = with pkgs; [
      rustup
      openssl
      pkg-config
    ];
  }

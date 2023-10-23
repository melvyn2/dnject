{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    nativeBuildInputs = with pkgs; [
      qt5.qtbase.dev
      libglvnd.dev
    ];
}

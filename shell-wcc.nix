# { pkgs ? import <nixpkgs> { crossSystem.config = "x86_64-w64-mingw32"; } }:
{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs.buildPackages.buildPackages; [
    wineWowPackages.stable
    cmake
    qt5.qtbase.dev
    qt5.qttools.dev
    libglvnd.dev
    # gcc
  ];

  depsBuildBuild = with pkgs; [
    pkgsCross.mingwW64.stdenv.cc
    pkgsCross.mingwW64.windows.pthreads
  ];

  shellHook = ''
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS="-C link-args=''$(echo $NIX_LDFLAGS | tr ' ' '\n' | grep -- '^-L' | tr '\n' ' ')"
    export NIX_LDFLAGS=
  '';
}


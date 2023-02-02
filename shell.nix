{ pkgs ? import ./nix/nixpkgs.nix { } }:
with pkgs;
let
  pulumi-bin' =
    let
      data = import ./nix/pulumi-bin-data.nix { };
    in
    pulumi-bin.overrideAttrs (finalAttrs: previousAttrs: {
      version = data.version;
      srcs = map (x: fetchurl x) data.pulumiPkgs.${stdenv.hostPlatform.system};
      meta.platforms = builtins.attrNames data.pulumiPkgs;
    });
in
# Ensure the overridden version of Pulumi is not older than the version in the pinned Nixpkgs.
assert -1 != builtins.compareVersions pulumi-bin'.version pulumi-bin.version;
mkShell {
  buildInputs = [
    awscli2
    gnumake
    # gnused # force Linux `sed` everywhere
    nixfmt
    nodejs-16_x # for Pulumi
    pulumi-bin'
    # saml2aws
  ];
}

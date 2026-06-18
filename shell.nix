{ pkgs ? import ./nix/nixpkgs.nix { } }:
with pkgs;
mkShell {
  buildInputs = [
    awscli2
    gnumake
    # gnused # force Linux `sed` everywhere
    nixfmt
    nodejs_22 # for Pulumi
    pulumi
    pulumiPackages.pulumi-nodejs
    # saml2aws
    wireguard-tools
  ];
}

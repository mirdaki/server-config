{ ... }:

{
  imports = [
    ./authentik.nix
    ./authelia.nix
    ./firewall.nix
    ./nextcloud.nix
    ./postgresql.nix
    ./security.nix
    ./silverbullet.nix
    ./ssh.nix
    ./user.nix
  ];
}

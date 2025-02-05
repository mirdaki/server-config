# Partly auto-generated using compose2nix v0.3.2-pre.

# To login to Tailscale with SSO, you'll need to run this, have it register the node, but not do auth
# Then get the node key from headscale via `headscale nodes list -o json` and use that to manually login with this URL
# https://net.codecaptured.com:443/oidc/register/nodekey:XXXXX

# Then to make it useable, see these headscale instructions
# https://headscale.net/stable/ref/exit-node/#on-the-control-server

# References
# - https://lemmy.world/post/7281194
# - https://github.com/qdm12/gluetun/discussions/2201

# Next steps:
# - Add option for location and description for names of systemd services, containers, and networks
# - Quickly see if setting ProtonVPN DNS works. Will disable DOT
# - Remove previous node and try creating a few

# TODO: Look into making this rootless. I tried once and kept running into issues. I had done:
# - Created a system user with linger, it's own home in /var/lib, and UID and GID subranges
# - Added that user and group to the systemd services as well as create a StateDirectory under the user home
# - A bunch of "tmpfiles" that weren't being created automatically in the home directory

{
  config,
  pkgs,
  lib,
  ...
}:

let
  cfg = config.protonvpn-exit-node;
  exitNodeType = lib.types.submodule {
    options = {
      serverCity = lib.mkOption { type = lib.types.str; };
      identifier = lib.mkOption { type = lib.types.str; };

      wireguardPrivateKeyFile = lib.mkOption { type = lib.types.str; };
      tailscaleAuthKeyFile = lib.mkOption { type = lib.types.str; };
    };
  };
in
{
  options = {
    protonvpn-exit-node.enable = lib.mkEnableOption "enable protonvpn-exit-node module";

    protonvpn-exit-node.nodes = lib.mkOption { type = lib.types.attrsOf exitNodeType; };

    # protonvpn-exit-node.name = lib.mkOption { type = lib.types.str; };
    # protonvpn-exit-node.serverCity = lib.mkOption { type = lib.types.str; };

    # protonvpn-exit-node.wireguardPrivateKeyFile = lib.mkOption { type = lib.types.str; };
    # protonvpn-exit-node.tailscaleAuthKeyFile = lib.mkOption { type = lib.types.str; };
  };

  config = lib.mkIf cfg.enable {
    # Runtime
    virtualisation.podman = {
      enable = true;
      autoPrune.enable = true;
      dockerCompat = true;
      defaultNetwork.settings = {
        # Required for container networking to be able to use names.
        dns_enabled = true;
      };
    };

    # Enable container name DNS for non-default Podman networks.
    # https://github.com/NixOS/nixpkgs/issues/226365
    networking.firewall.interfaces."podman+".allowedUDPPorts = [ 53 ];

    virtualisation.oci-containers.backend = "podman";

    # Create base directory
    systemd.tmpfiles.rules = lib.concatMap (node: [
      "d /var/lib/protonvpn-exit-node-${node.identifier}/gluetun"
      "d /var/lib/protonvpn-exit-node-${node.identifier}/tailscale/state"
      "d /var/lib/protonvpn-exit-node-${node.identifier}/tailscale/var/lib"
    ]) (lib.attrValues cfg.nodes);

    # ProtonVPN outgoing traffic
    virtualisation.oci-containers.containers = lib.concatMap (node: {

      "gluetun-${node.identifier}" = {
        image = "ghcr.io/qdm12/gluetun:v3.39.1";
        environment = {
          "SERVER_CITIES" = "${node.serverCity}";
          "UPDATER_PERIOD" = "24h";
          "TZ" = "America/Los_Angeles";
          "VPN_SERVICE_PROVIDER" = "protonvpn";
          "VPN_TYPE" = "wireguard";
          "WIREGUARD_PRIVATE_KEY_SECRETFILE" = "WIREGUARD_PRIVATE_KEY_SECRETFILE";
          "FIREWALL_OUTBOUND_SUBNETS" = "100.64.0.0/10";
          "DOT" = "on";
          "DOT_PROVIDERS" = "quad9";
        };
        volumes = [
          "/var/lib/protonvpn-exit-node-${node.identifier}/gluetun:/gluetun:rw"
          "${node.wireguardPrivateKeyFile}:/WIREGUARD_PRIVATE_KEY_SECRETFILE:ro"
        ];
        log-driver = "journald";
        extraOptions = [
          "--cap-add=NET_ADMIN"
          "--device=/dev/net/tun:/dev/net/tun:rwm"
          "--network-alias=gluetun-${node.identifier}"
          "--network=protonvpn-exit-node-${node.identifier}_default"
        ];
      };

      "tailscale-${node.identifier}" = {
        image = "ghcr.io/tailscale/tailscale:v1.76.6";
        environment = {
          "TS_AUTHKEY" = "file:/TS_AUTHKEY";
          "TS_EXTRA_ARGS" = "--login-server=https://net.codecaptured.com --advertise-exit-node";
          "TS_HOSTNAME" = "protonvpn-${node.identifier}";
          "TS_STATE_DIR" = "/state";
          "TS_ROUTES" = "100.64.0.0/10";
        };
        volumes = [
          "/dev/net/tun:/dev/net/tun:rw"
          "/var/lib/protonvpn-exit-node-${node.identifier}/tailscale/state:/state:rw"
          "/var/lib/protonvpn-exit-node-${node.identifier}/tailscale/var/lib:/var/lib:rw"
          "${node.tailscaleAuthKeyFile}:/TS_AUTHKEY:ro"
        ];
        dependsOn = [ "gluetun-${node.identifier}" ];
        log-driver = "journald";
        extraOptions = [
          "--cap-add=NET_ADMIN"
          "--cap-add=NET_RAW"
          "--network=container:gluetun-${node.identifier}"
        ];
      };
    }) (lib.attrValues cfg.nodes);

    # systemd.services = lib.concatMap (node: {
    #   "podman-gluetun-${node.identifier}" = {
    #     serviceConfig = {
    #       Restart = lib.mkOverride 90 "always";
    #     };
    #     after = [ "podman-network-protonvpn-exit-node-${node.identifier}_default.service" ];
    #     requires = [ "podman-network-protonvpn-exit-node-${node.identifier}_default.service" ];
    #     partOf = [ "podman-compose-protonvpn-exit-node-${node.identifier}-root.target" ];
    #     wantedBy = [ "podman-compose-protonvpn-exit-node-${node.identifier}-root.target" ];
    #   };

    #   "podman-tailscale-${node.identifier}" = {
    #     serviceConfig = {
    #       Restart = lib.mkOverride 90 "always";
    #     };
    #     partOf = [ "podman-compose-protonvpn-exit-node-${node.identifier}-root.target" ];
    #     wantedBy = [ "podman-compose-protonvpn-exit-node-${node.identifier}-root.target" ];
    #   };

    #   "podman-network-protonvpn-exit-node-${node.identifier}_default" = {
    #     path = [ pkgs.podman ];
    #     serviceConfig = {
    #       Type = "oneshot";
    #       RemainAfterExit = true;
    #       ExecStop = "podman network rm -f protonvpn-exit-node-${node.identifier}_default";
    #     };
    #     script = ''
    #       podman network inspect protonvpn-exit-node-${node.identifier}_default || podman network create protonvpn-exit-node-${node.identifier}_default
    #     '';
    #     partOf = [ "podman-compose-protonvpn-exit-node-${node.identifier}-root.target" ];
    #     wantedBy = [ "podman-compose-protonvpn-exit-node-${node.identifier}-root.target" ];
    #   };
    # }) (lib.attrValues cfg.nodes);

    # Tailscale exit node
    # virtualisation.oci-containers.containers = lib.concatMap (node: {

    # }) (lib.attrValues cfg.nodes);

    # systemd.services = lib.concatMap (node: {

    # }) (lib.attrValues cfg.nodes);

    # Networks
    # systemd.services = lib.concatMap (node: {

    # }) (lib.attrValues cfg.nodes);

    # Root service
    # When started, this will automatically create all resources and start
    # the containers. When stopped, this will teardown all resources.
    # systemd.targets = lib.concatMap (node: {
    #   "podman-compose-protonvpn-exit-node-${node.identifier}-root" = {
    #     unitConfig = {
    #       Description = "Root target generated by compose2nix.";
    #     };
    #     wantedBy = [ "multi-user.target" ];
    #   };
    # }) (lib.attrValues cfg.nodes);
  };
}

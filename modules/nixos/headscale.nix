{
  lib,
  config,
  pkgs,
  ...
}:

let
  cfg = config.headscale;
in
{
  options = {
    headscale.enable = lib.mkEnableOption "enable headscale module";

    headscale.domainName = lib.mkOption { type = lib.types.str; };

    headscale.adminpassFile = lib.mkOption { type = lib.types.str; };
  };

  config = lib.mkIf cfg.enable {
    services.nginx = {
      enable = true;
      virtualHosts = {
        ${cfg.domainName} = {
          forceSSL = false;
          enableACME = false;
        };
      };
    };

    services.headscale = {
      enable = true;
    };
  };
}

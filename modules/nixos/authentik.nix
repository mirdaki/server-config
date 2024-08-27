{
  lib,
  config,
  pkgs,
  ...
}:

let
  cfg = config.authentik;
in
{
  options = {
    authentik.enable = lib.mkEnableOption "enable authentik module";

    authentik.domainName = lib.mkOption { type = lib.types.str; };

    authentik.environmentFile = lib.mkOption { type = lib.types.str; };
  };

  config = lib.mkIf cfg.enable {
    services.nginx = {
      enable = true;
      virtualHosts = {
        ${cfg.domainName} = {
          forceSSL = false;
          enableACME = false;
          #   locations."/" = {
          #     proxyPass = "http://localhost:3000";
          #   };
        };
      };
    };

    services.authentik = {
      enable = true;
      environmentFile = cfg.environmentFile;
      settings = {
        email = {
          host = "smtp.example.com";
          port = 587;
          username = "authentik@example.com";
          use_tls = false;
          use_ssl = false;
          from = "authentik@example.com";
        };
        disable_startup_analytics = true;
        avatars = "initials";
      };
    };
  };
}

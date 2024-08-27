{
  lib,
  config,
  pkgs,
  ...
}:

let
  cfg = config.silverbullet;
in
{
  options = {
    silverbullet.enable = lib.mkEnableOption "enable silverbullet module";

    silverbullet.domainName = lib.mkOption { type = lib.types.str; };

    silverbullet.spaceDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/silverbullet";
    };
  };

  config = lib.mkIf cfg.enable {
    services.nginx = {
      enable = true;
      virtualHosts = {
        ${cfg.domainName} = {
          forceSSL = false;
          enableACME = false;
          locations."/" = {
            # proxyPass = "http://localhost:3000";
            extraConfig = ''
                include /etc/nginx/snippets/proxy.conf;
                include /etc/nginx/snippets/authelia-authrequest.conf;
                proxy_pass $upstream;
            '';
          };
          extraConfig = ''
            set $upstream http://localhost:3000;
            #include /etc/nginx/snippets/ssl.conf;
            include /etc/nginx/snippets/authelia-location.conf;
          '';
        };
      };
    };

    services.silverbullet = {
      enable = true;
      #   spaceDir = cfg.spaceDir;
    };
  };
}

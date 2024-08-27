{
  lib,
  config,
  pkgs,
  ...
}:

let
  cfg = config.nextcloud;
in
{
  options = {
    nextcloud.enable = lib.mkEnableOption "enable nextcloud module";

    nextcloud.domainName = lib.mkOption { type = lib.types.str; };

    nextcloud.adminpassFile = lib.mkOption { type = lib.types.str; };
  };

  config = lib.mkIf cfg.enable {
    services.nginx = {
      enable = true;

      # Use recommended settings
      recommendedGzipSettings = true;
      recommendedOptimisation = true;
      recommendedProxySettings = true;
      recommendedTlsSettings = true;

      # Only allow PFS-enabled ciphers with AES256
      sslCiphers = "AES256+EECDH:AES256+EDH:!aNULL";

      # Setup Nextcloud virtual host to listen on ports
      virtualHosts = {
        ${cfg.domainName} = {
          # Force HTTP redirect to HTTPS
          forceSSL = false;
          # LetsEncrypt
          enableACME = false;
        };
      };
    };

    services.nextcloud = {
      enable = true;
      package = pkgs.nextcloud29;
      hostName = cfg.domainName;
      autoUpdateApps.enable = true;
      # Needed?
      autoUpdateApps.startAt = "05:00:00";
      maxUploadSize = "16G";
      # Suggested by Nextcloud's health check.
      phpOptions."opcache.interned_strings_buffer" = "16";

      settings = {
        default_phone_region = "US";
        # Missing an array index?
        # user_oidc.use_pkce = true;
      };

      config = {
        dbtype = "pgsql";
        dbhost = "/run/postgresql";
        adminuser = "admin";
        adminpassFile = cfg.adminpassFile;
      };

      extraApps = with config.services.nextcloud.package.packages.apps; {
        # List of apps we want to install and are already packaged in
        # https://github.com/NixOS/nixpkgs/blob/master/pkgs/servers/nextcloud/packages/nextcloud-apps.json
        inherit
          calendar
          contacts
          gpoddersync
          memories
          # user_oidc
          ;
      };
    };

    services.postgresql = {
      # Ensure the database, user, and permissions always exist
      ensureDatabases = [ "nextcloud" ];
      ensureUsers = [
        {
          name = "nextcloud";
          ensureDBOwnership = true;
        }
      ];
    };

    # Nextcloud has error logs if not included, though it will eventually load correctly
    systemd.services."nextcloud-setup" = {
      requires = [ "postgresql.service" ];
      after = [ "postgresql.service" ];
    };
  };
}

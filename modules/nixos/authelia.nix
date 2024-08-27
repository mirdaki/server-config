{
  lib,
  config,
  pkgs,
  ...
}:

let
  cfg = config.authelia;
in
{
  options = {
    authelia.enable = lib.mkEnableOption "enable authelia module";

    authelia.domainName = lib.mkOption { type = lib.types.str; };

    # authelia.jwtSecretFile = lib.mkOption { type = lib.types.str; };
  };

  config = lib.mkIf cfg.enable {
    services.nginx = {
      enable = true;
      virtualHosts = {
        ${cfg.domainName} = {
          forceSSL = false;
          enableACME = false;
          locations."/" = {
            proxyPass = "http://127.0.0.1:9091";
            proxyWebsockets = true;
          };
        };
      };
    };

    services.authelia.instances = {
      main = {
        enable = true;
        secrets.storageEncryptionKeyFile = "/etc/authelia/storageEncryptionKeyFile";
        secrets.jwtSecretFile = "/etc/authelia/jwtSecretFile";
        settingsFiles = [ "/etc/authelia/configuration.yml" ];
        # settings = {
        #   # authentication_backend.file.path = "/etc/authelia/users_database.yml";
        #   # access_control.default_policy = "one_factor";
        #   # session.domain = cfg.domainName;
        #   # session.domain = "127.0.0.1:9091";
        #   # storage.local.path = "/tmp/db.sqlite3";
        #   # notifier.filesystem.filename = "/tmp/notifications.txt";
        #   # theme = "auto";
        #   # default_2fa_method = "totp";
        #   # log.level = "debug";

        #   # server.disable_healthcheck = true;
        #   # # Setup for Nextcloud
        #   # identity_providers.oidc

        #   # access_control.rules.domain."notes.i.codecaptured.com" = {
        #   #   resource = [
        #   #     "/.client/manifest.json$"
        #   #     "/.client/[a-zA-Z0-9_-]+.png$" 
        #   #     "/service_worker.js$"
        #   #   ];
        #   #   policy = "bypass";
        #   # };

        #   # server.endpoints.authz.auth-request.implementation = "AuthRequest";
        #   # session.cookies = {
        #   #   domain = "i.codecaptured.com";
        #   #   authelia_url = "http://auth.i.codecaptured.com";
        #   #   default_redirection_url = "http://www.i.codecaptured.com";
        #   # };
        # };
      };
    };

    environment.etc."authelia/storageEncryptionKeyFile" = {
      mode = "0777";
      user = "authelia-main";
      text = "you_must_generate_a_random_string_of_more_than_twenty_chars_and_configure_this";
    };
    environment.etc."authelia/jwtSecretFile" = {
      mode = "0777";
      user = "authelia-main";
      text = "a_very_important_secret";
    };
    environment.etc."authelia/users_database.yml" = {
      mode = "0777";
      user = "authelia-main";
      text = ''
        users:
          bob:
            disabled: false
            displayname: bob
            # password of password
            password: $argon2id$v=19$m=65536,t=3,p=4$2ohUAfh9yetl+utr4tLcCQ$AsXx0VlwjvNnCsa70u4HKZvFkC8Gwajr2pHGKcND/xs
            email: bob@jim.com
            groups:
              - admin
              - dev
      '';
    };
    # With config from https://silverbullet.md/Authelia
    environment.etc."authelia/configuration.yml" = {
      mode = "0777";
      user = "authelia-main";
      text = ''
server:
  host: 0.0.0.0
  port: 9091
  endpoints:
    authz:
      auth-request:
        implementation: 'AuthRequest'

notifier:
  filesystem:
    filename: /tmp/notifications.txt

storage:
  local:
    path: /tmp/db.sqlite3

authentication_backend:
  file:
    path: /etc/authelia/users_database.yml
    password:
      algorithm: argon2id
      iterations: 1
      salt_length: 16
      parallelism: 8
      memory: 64

access_control:
  default_policy: deny
  rules:
    - domain: notes.i.codecaptured.com
      resources:
        - '/.client/manifest.json$'
        - '/.client/[a-zA-Z0-9_-]+.png$'
        - '/service_worker.js$'
      policy: bypass
    - domain: '*.i.codecaptured.com'
      policy: one_factor

session:
  domain: 'auth.i.codecaptured.com'
  secret: 'insecure_session_secret'
  name: 'authelia_session'
  same_site: 'lax'
  inactivity: '5m'
  expiration: '1h'
  remember_me: '1M'
  # cookies:
  #   - domain: 'i.codecaptured.com'
  #     authelia_url: 'http://auth.i.codecaptured.com'
  #     default_redirection_url: 'http://www.i.codecaptured.com'
  #     name: 'authelia_session'
  #     same_site: 'lax'
  #     inactivity: '5m'
  #     expiration: '1h'
  #     remember_me: '1d'
      '';
    };

    environment.etc."nginx/snippets/authelia-location.conf" = {
      mode = "0777";
      user = "authelia-main";
      text = ''
        set $upstream_authelia http://127.0.0.1:9091/api/authz/auth-request;

        ## Virtual endpoint created by nginx to forward auth requests.
        location /internal/authelia/authz {
            ## Essential Proxy Configuration
            internal;
            proxy_pass $upstream_authelia;

            ## Headers
            ## The headers starting with X-* are required.
            proxy_set_header X-Original-Method $request_method;
            proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header Content-Length "";
            proxy_set_header Connection "";

            ## Basic Proxy Configuration
            proxy_pass_request_body off;
            proxy_next_upstream error timeout invalid_header http_500 http_502 http_503; # Timeout if the real server is dead
            proxy_redirect http:// $scheme://;
            proxy_http_version 1.1;
            proxy_cache_bypass $cookie_session;
            proxy_no_cache $cookie_session;
            proxy_buffers 4 32k;
            client_body_buffer_size 128k;

            ## Advanced Proxy Configuration
            send_timeout 5m;
            proxy_read_timeout 240;
            proxy_send_timeout 240;
            proxy_connect_timeout 240;
        }
      '';
    };
    environment.etc."nginx/snippets/authelia-authrequest.conf" = {
      mode = "0777";
      user = "authelia-main";
      text = ''
        ## Send a subrequest to Authelia to verify if the user is authenticated and has permission to access the resource.
        auth_request /internal/authelia/authz;

        ## Save the upstream metadata response headers from Authelia to variables.
        auth_request_set $user $upstream_http_remote_user;
        auth_request_set $groups $upstream_http_remote_groups;
        auth_request_set $name $upstream_http_remote_name;
        auth_request_set $email $upstream_http_remote_email;

        ## Inject the metadata response headers from the variables into the request made to the backend.
        proxy_set_header Remote-User $user;
        proxy_set_header Remote-Groups $groups;
        proxy_set_header Remote-Email $email;
        proxy_set_header Remote-Name $name;

        ## Configure the redirection when the authz failure occurs. Lines starting with 'Modern Method' and 'Legacy Method'
        ## should be commented / uncommented as pairs. The modern method uses the session cookies configuration's authelia_url
        ## value to determine the redirection URL here. It's much simpler and compatible with the mutli-cookie domain easily.

        ## Modern Method: Set the $redirection_url to the Location header of the response to the Authz endpoint.
        auth_request_set $redirection_url $upstream_http_location;

        ## Modern Method: When there is a 401 response code from the authz endpoint redirect to the $redirection_url.
        error_page 401 =302 $redirection_url;

        ## Legacy Method: Set $target_url to the original requested URL.
        ## This requires http_set_misc module, replace 'set_escape_uri' with 'set' if you don't have this module.
        # set_escape_uri $target_url $scheme://$http_host$request_uri;

        ## Legacy Method: When there is a 401 response code from the authz endpoint redirect to the portal with the 'rd'
        ## URL parameter set to $target_url. This requires users update 'auth.example.com/' with their external authelia URL.
        # error_page 401 =302 https://auth.i.codecaptured.com/?rd=$target_url;
      '';
    };
    environment.etc."nginx/snippets/proxy.conf" = {
      mode = "0777";
      user = "authelia-main";
      text = ''
        ## Headers
        proxy_set_header Host $host;
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-URI $request_uri;
        # proxy_set_header X-Forwarded-Ssl on;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;

        ## Basic Proxy Configuration
        client_body_buffer_size 128k;
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503; ## Timeout if the real server is dead.
        proxy_redirect  http://  $scheme://;
        proxy_http_version 1.1;
        proxy_cache_bypass $cookie_session;
        proxy_no_cache $cookie_session;
        proxy_buffers 64 256k;

        ## Trusted Proxies Configuration
        ## Please read the following documentation before configuring this:
        ##     https://www.authelia.com/integration/proxies/nginx/#trusted-proxies
        # set_real_ip_from 10.0.0.0/8;
        # set_real_ip_from 172.16.0.0/12;
        # set_real_ip_from 192.168.0.0/16;
        # set_real_ip_from fc00::/7;
        real_ip_header X-Forwarded-For;
        real_ip_recursive on;

        ## Advanced Proxy Configuration
        send_timeout 5m;
        proxy_read_timeout 360;
        proxy_send_timeout 360;
        proxy_connect_timeout 360;
      '';
    };

    # TODO: The 443 redirect here will likely cause issues
    environment.etc."nginx/site-confs/auth.conf" = {
      mode = "0777";
      user = "authelia-main";
      text = ''
        server {
            listen 80;
            server_name auth.*;

            include /config/nginx/snippets/ssl.conf;

            set $upstream http://auth.i.codecaptured.com;

            location / {
                include /config/nginx/snippets/proxy.conf;
                proxy_pass $upstream;
            }

            location = /api/verify {
                proxy_pass $upstream;
            }

            location /api/authz/ {
                proxy_pass $upstream;
            }
            # return 301 https://$server_name$request_uri;
        }

        # server {
        #     listen 443 ssl http2;
        #     server_name auth.*;

        #     include /config/nginx/snippets/ssl.conf;

        #     set $upstream http://authelia:9091;

        #     location / {
        #         include /config/nginx/snippets/proxy.conf;
        #         proxy_pass $upstream;
        #     }

        #     location = /api/verify {
        #         proxy_pass $upstream;
        #     }

        #     location /api/authz/ {
        #         proxy_pass $upstream;
        #     }
        # }
      '';
    };

    networking.extraHosts = ''
      127.0.0.1 auth.i.codecaptured.com
    '';

    # environment.etc."nginx/snippets/" = {
    #   mode = "0777";
    #   user = "authelia-main";
    #   text = ''
    #   '';
    # };
    # environment.etc."nginx/snippets/" = {
    #   mode = "0777";
    #   user = "authelia-main";
    #   text = ''
    #   '';
    # };

    # environment.etc."nginx/snippets/authelia.conf" = {
    #   mode = "0777";
    #   user = "authelia-main";
    #   text = ''
    #     # Virtual endpoint created by nginx to forward auth requests.
    #     location /authelia {
    #         internal;
    #         set $upstream_authelia http://127.0.0.1:9091/api/verify;
    #         proxy_pass_request_body off;
    #         proxy_pass $upstream_authelia;
    #         proxy_set_header Content-Length "";

    #         # Timeout if the real server is dead
    #         proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;

    #         # [REQUIRED] Needed by Authelia to check authorizations of the resource.
    #         # Provide either X-Original-URL and X-Forwarded-Proto or
    #         # X-Forwarded-Proto, X-Forwarded-Host and X-Forwarded-Uri or both.
    #         # Those headers will be used by Authelia to deduce the target url of the     user.
    #         # Basic Proxy Config
    #         client_body_buffer_size 128k;
    #         proxy_set_header Host $host;
    #         proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    #         proxy_set_header X-Real-IP $remote_addr;
    #         proxy_set_header X-Forwarded-For $remote_addr;
    #         proxy_set_header X-Forwarded-Proto $scheme;
    #         proxy_set_header X-Forwarded-Host $http_host;
    #         proxy_set_header X-Forwarded-Uri $request_uri;
    #         proxy_set_header X-Forwarded-Ssl on;
    #         proxy_redirect  http://  $scheme://;
    #         proxy_http_version 1.1;
    #         proxy_set_header Connection "";
    #         proxy_cache_bypass $cookie_session;
    #         proxy_no_cache $cookie_session;
    #         proxy_buffers 4 32k;

    #         # Advanced Proxy Config
    #         send_timeout 5m;
    #         proxy_read_timeout 240;
    #         proxy_send_timeout 240;
    #         proxy_connect_timeout 240;
    #     }
    #   '';
    # };
    # environment.etc."nginx/snippets/auth.conf" = {
    #   mode = "0777";
    #   user = "authelia-main";
    #   text = ''
    #     # Basic Authelia Config
    #     # Send a subsequent request to Authelia to verify if the user is authenticated
    #     # and has the right permissions to access the resource.
    #     auth_request /authelia;
    #     # Set the `target_url` variable based on the request. It will be used to build the portal
    #     # URL with the correct redirection parameter.
    #     auth_request_set $target_url $scheme://$http_host$request_uri;
    #     # Set the X-Forwarded-User and X-Forwarded-Groups with the headers
    #     # returned by Authelia for the backends which can consume them.
    #     # This is not safe, as the backend must make sure that they come from the
    #     # proxy. In the future, it's gonna be safe to just use OAuth.
    #     auth_request_set $user $upstream_http_remote_user;
    #     auth_request_set $groups $upstream_http_remote_groups;
    #     auth_request_set $name $upstream_http_remote_name;
    #     auth_request_set $email $upstream_http_remote_email;
    #     proxy_set_header Remote-User $user;
    #     proxy_set_header Remote-Groups $groups;
    #     proxy_set_header Remote-Name $name;
    #     proxy_set_header Remote-Email $email;
    #     # If Authelia returns 401, then nginx redirects the user to the login portal.
    #     # If it returns 200, then the request pass through to the backend.
    #     # For other type of errors, nginx will handle them as usual.
    #     error_page 401 =302 https://auth.example.com/?rd=$target_url;
    #   '';
    # };
  };
}

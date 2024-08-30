# Computer Config

## NixOS Configuration

To update the computer, run the below with the right profile (`#alderaan` below):

```bash
sudo nixos-rebuild switch --flake ~/computer-config#alderaan
```

### First Time Setup

Note: I ran into issues (where to put the sops secret, clone the config too, the default ssh blocking root) having just a root user. There is a dependency problem since this config sets up the user and their password. This can be solved with ad-hoc steps (get the config as root, generate a secret as root, build with the user but without ssh steps, then migrate the config to the users directory and clean up). But that's not clean. A future option might be to create a user with a default password or with an empty password to start with, then do these steps. Need to investigate further.

This may not be needed going forward, but I did need this to use experimental features (nix command and flakes) in CLI ad hoc:

```bash
nix-shell -p git 
git clone https://github.com/mirdaki/computer-config.git

nix run home-manager/master --extra-experimental-features nix-command --extra-experimental-features flakes -- init
```

If you need to create age keys for secrets, [follow these steps](https://github.com/Mic92/sops-nix?tab=readme-ov-file#usage-example), but use the below commands to not need to install `age-keygen`:
```bash
nix shell nixpkgs#age -c age-keygen -o ~/.config/sops/age/keys.txt
# or to get the public key if it already exists
nix shell nixpkgs#age -c age-keygen -y ~/.config/sops/age/keys.txt
```

[Setting up a user password with sops-nix](https://github.com/Mic92/sops-nix?tab=readme-ov-file#setting-a-users-password). Note: The value you put in the secrets file is a hash of the password from `mkpasswd`, not the password itself.

### Updaing Secrets

```bash
cd hosts/alderaan/
nix-shell -p sops --run "sops secrets/secret.yaml"
```

#### Nextcloud

For some reason, despite trying multiple examples, the initial admin password I set never allowed logging in to the Nextcloud web UI. I can change it via the occ CLI tool and successfully login.

```bash
nextcloud-occ user:resetpassword root
```

## Old Manual Docker, to be updated
- Setup Ubuntu 18.04
	- `ansible-playbook -l coruscant -i initial-config/hosts -u root initial-config/setup_ubuntu1804/playbook.yml`
		- May need to change user on subsequent runs
	- Reboot (Must be separate command, because root connections no longer work)
		- `ansible coruscant -i initial-config/hosts -u matthew -m reboot -b`
- Install Docker Ubuntu 18.04
	- `ansible-playbook -l coruscant -i initial-config/hosts -u matthew initial-config/docker_ubuntu1804/playbook.yml`
- Install Matrix
	- Initial install
		- `ansible-playbook -i matrix/inventory/hosts matrix/setup.yml --tags=setup-all --skip-tags=setup-mx-puppet-discord`
	- Start services
		- `ansible-playbook -i matrix/inventory/hosts matrix/setup.yml --tags=start`
	- Check install
		- `ansible-playbook -i matrix/inventory/hosts matrix/setup.yml --tags=self-check`
	- Add users
		- `ansible-playbook -i matrix/inventory/hosts matrix/setup.yml --extra-vars='username=<name> password=<your-password> admin=yes' --tags=register-user`
	- Uncomment Dimension and add it
	- Send invite to new users
		- `ansible-playbook -i matrix/inventory/hosts setup.yml --tags=generate-matrix-registration-token --extra-vars="one_time=yes ex_date=2021-12-31"`
		- Send the user that token and direct them to https://matrix.DOMAIN/matrix-registration/register

### Problems

- If a container fails to run properly on `start`, try restarting docker `sudo systemctl restart docker` and running the command again

## Resources

- [Matrix](https://github.com/spantaleev/matrix-docker-ansible-deploy)

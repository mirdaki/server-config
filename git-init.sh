#!/bin/bash
# sets up a pre-commit hook to ensure that vault.yaml is encrypted
#
# From NickBusey via ironicbadger
# https://gitlab.com/NickBusey/HomelabOS/-/issues/355

if [ -d .git/ ]; then
rm .git/hooks/pre-commit
cat <<EOT >> .git/hooks/pre-commit
if ( cat group_vars/workstations/vault.yml | grep -q "\$ANSIBLE_VAULT;" ); then
    echo "[38;5;108mVault Encrypted. Safe to commit.[0m"
else
    echo "[38;5;208mVault not encrypted! Encrypt and try again.[0m"
    exit 1
fi

EOT

fi

chmod +x .git/hooks/pre-commit

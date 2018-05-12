vault secrets disable trust
vault delete sys/plugins/catalog/trustee
cd ..
go build
mv trustee $HOME/etc/vault.d/vault_plugins
export SHA256=$(shasum -a 256 "$HOME/etc/vault.d/vault_plugins/trustee" | cut -d' ' -f1)
vault write sys/plugins/catalog/trustee \
      sha_256="${SHA256}" \
      command="trustee --ca-cert=$HOME/etc/vault.d/root.crt --client-cert=$HOME/etc/vault.d/vault.crt --client-key=$HOME/etc/vault.d/vault.key"
vault secrets enable -path=trust -plugin-name=trustee plugin

## Trustee API

Vault provides a CLI that wraps the Vault REST interface. Any HTTP client (including the Vault CLI) can be used for accessing the API. Since the REST API produces JSON, I use the wonderful [jq](https://stedolan.github.io/jq/) for the examples.

* [List Trustees](https://github.com/immutability-io/vault-ethereum/blob/master/API.md#list-trustees)
* [Read Trustee](https://github.com/immutability-io/vault-ethereum/blob/master/API.md#read-trustee)
* [Create Trustee](https://github.com/immutability-io/vault-ethereum/blob/master/API.md#create-trustee)
* [Update Trustee](https://github.com/immutability-io/vault-ethereum/blob/master/API.md#update-trusteere-encrypt-keystore)
* [Delete Trustee](https://github.com/immutability-io/vault-ethereum/blob/master/API.md#delete-trustee)
* [Import Trustee](https://github.com/immutability-io/vault-ethereum/blob/master/API.md#import-trustee)
* [Export Trustee](https://github.com/immutability-io/vault-ethereum/blob/master/API.md#export-trustee)

### LIST TRUSTEES

This endpoint will list all trustees stores at a path.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `LIST`  | `:mount-path/trustees`  | `200 application/json` |

#### Parameters

* `path` (`string: <required>`) - Specifies the path of the trustees to list. This is specified as part of the URL.

#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request LIST \
    https://localhost:8200/v1/trust/trustees | jq .
```

#### Sample Response

The example below shows output for a query path of `/trust/trustees/` when there are 2 trustees at `/trust/trustees/test` and `/trust/trustees/test2`.

```
{
  "request_id": "f5689b77-ff54-8aed-27e0-1be52ab4fd61",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "keys": [
      "test",
      "test2"
    ]
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}

```

### READ ACCOUNT

This endpoint will list details about the Ethereum trustee at a path.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `GET`  | `:mount-path/trustees/:name`  | `200 application/json` |

#### Parameters

* `name` (`string: <required>`) - Specifies the name of the trustee to read. This is specified as part of the URL.

#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request GET \
    https://localhost:8200/v1/trust/trustees/test | jq .
```

#### Sample Response

The example below shows output for a read of `/trust/trustees/test`.

```
{
  "request_id": "fe52ec63-80a4-08f5-3780-ac8bd68a8450",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "address": "0x3943FF61FF803316cF02938b5b0b3Ba3bbE183e4"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```


### CREATE TRUSTEE

This endpoint will create a trustee at a path.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/trustees/:name`  | `200 application/json` |

#### Parameters

* `name` (`string: <required>`) - Specifies the name of the trustee to create. This is specified as part of the URL.

#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    https://localhost:8200/v1/trust/trustees/test3 | jq .
```

#### Sample Response

The example below shows output for the successful creation of `/trust/trustees/test3`.

```
{
  "request_id": "8bfbe4f9-5f8b-1599-27da-172b04c5b8df",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "address": "0xb7633a740Df793CbF7530b251c89aecA4F4df748"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```


### DELETE TRUSTEE

This endpoint will delete the trustee - and its passphrase - from Vault.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `DELETE`  | `:mount-path/trustees/:name`  | `200 application/json` |

#### Parameters

* `name` (`string: <required>`) - Specifies the name of the trustee to update. This is specified as part of the URL.

#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request DELETE \
    https://localhost:8200/v1/trust/trustees/test3
```

#### Sample Response

There is no response payload.

### IMPORT TRUSTEE

This endpoint will import a JSON Keystore and passphrase into Vault at a path. It will create an trustee and map it to the `:mount-path/trustees/:name`. If an trustee already exists for this name, the operation fails.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/import/:name`  | `200 application/json` |

#### Parameters

* `name` (`string: <required>`) - Specifies the name of the trustee to create. This is specified as part of the URL.
* `path` (`string: <required>`) - The path of the JSON keystore file.
* `passphrase` (`string: <required>`) - The `passphrase` that was used to encrypt the keystore.

#### Sample Payload

Be careful with those passphrases!

```sh
read -s PASSPHRASE; read  PAYLOAD_WITH_PASSPHRASE <<EOF
{"path":"/Users/immutability/.ethereum/keystore/UTC--2017-12-01T23-13-37.315592353Z--a152e7a09267bcff6c33388caab403b76b889939", "passphrase":"$PASSPHRASE"}
EOF
unset PASSPHRASE
```

#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data $PAYLOAD_WITH_PASSPHRASE \
    https://localhost:8200/v1/trust/import/test3 | jq .
    unset PAYLOAD_WITH_PASSPHRASE
```

#### Sample Response

The example below shows output for the successful creation of `/trust/trustees/test3`.

```
{
  "request_id": "c8b79326-74eb-c75e-a602-bd0609ba9a10",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "address": "0xa152E7a09267bcFf6C33388cAab403b76B889939"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

### EXPORT TRUSTEE

This endpoint will export a JSON Keystore for use in another wallet.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/trustees/:name/export`  | `200 application/json` |

#### Parameters

* `name` (`string: <required>`) - Specifies the name of the trustee to export. This is specified as part of the URL.
* `path` (`string: <required>`) - The directory where the JSON keystore file will be exported to.

#### Sample Payload

```sh
{
  "path":"/Users/immutability/.ethereum/keystore"
}
```
#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    https://localhost:8200/v1/trust/trustees/test/export | jq .
```

#### Sample Response

The example below shows output for the successful export of the keystore for `/trust/trustees/test`.

```
{
  "request_id": "9443b8cf-9bde-0790-5b5f-1a01e14629bc",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "passphrase": "synthesis-augmented-playhouse-squeeze-reapply-curry-sprite-surround-coleslaw",
    "path": "/Users/immutability/.ethereum/keystore/UTC--2018-02-02T00-19-34.618912520Z--060b8e95956b8e0423b011ea496e69eec0db136f"
  },
  "warnings": null
}
```



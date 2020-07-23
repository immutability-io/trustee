# trustee

A Vault plugin that solves for trust in a decentralized way

## Just the Facts Ma'am

Follows describes how to install and use the plugin.

### The Plugin Directory

Vault must be configured to be aware of plugins. This is done with a stanza in the Vault configuration file. Assume that `/Users/immutability/etc/vault.d/vault_plugins` is where you intend to place the binary files for the plugins. Then, your Vault configuration file needs to have this stanza:

```json
plugin_directory = "/Users/immutability/etc/vault.d/vault_plugins"
```

### The Plugin Catalog

Once the plugin resides in the directory, it needs to be added to the plugin catalog. Assume that the environment variable `HOME = /Users/immutability`.

```sh
export SHA256=$(shasum -a 256 "$HOME/etc/vault.d/vault_plugins/trustee" | cut -d' ' -f1)
vault write sys/plugins/catalog/secret/trustee \
      sha_256="${SHA256}" \
      command="trustee --ca-cert=$HOME/etc/vault.d/root.crt --client-cert=$HOME/etc/vault.d/vault.crt --client-key=$HOME/etc/vault.d/vault.key"
```

It should be noted that the 3 bits of key material used to define the command are the same that Vault uses for TLS. It should also be noted that write access to `sys/plugins/catalog/secret` should be restricted to the most privileged users in the Vault ecosystem.

### Enable the Plugin

Enabling the plugin amounts to mounting a path in Vault. The design of the path will usually follow some naming convention.

```sh
vault secrets enable -path=immutability/sandbox/trust -plugin-name=trustee plugin
```

### Configure the Plugin

The plugin supports IP whitelisting - which can be configured at the `immutability/sandbox/trust/config` endpoint.

### Create a Trustee

To sign a set of claims, a trustee must be created. This trustee has a name, a private key and an `address`. The address is a condensed form of a public key for the trustee's private key. To trust a set of claims, one simple adds this address to code (it is not sensitive) and matches on it. In this case, the name of the trustee is `root`.

```sh
$ vault write -f immutability/sandbox/trust/trustees/root
Key        Value
---        -----
address    0x30574b6564486de41c35488737b72eb223386c0c
```

### Sign a set of claims

THe `root` trustee is making a clain that `darwin` was the `watchmaker`. If you trust `root`, you trust the claims.

```sh
$ cat claims.json
{
    "watchmaker": "darwin"
}

$ vault write immutability/sandbox/trust/trustees/root/claim claims=@claims.json
Key          Value
---          -----
watchmaker   darwin
eth          0x4e995ee42fb40c4d00fb49c431d6e204880a546c868f39c1fea6c625bf8a53fc76f7f5de04a72fdc50114cd5f984a72b43f16e9680af89fadddd338b3147403600
exp          1595358607
iss          0x30574b6564486de41c35488737b72eb223386c0c
jti          a34a6299-1cc6-43c6-bab5-111cb2ba5013
jwt          eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb21taXR0ZXIiOiJqcGxvdWdoIiwiZXRoIjoiMHg0ZTk5NWVlNDJmYjQwYzRkMDBmYjQ5YzQzMWQ2ZTIwNDg4MGE1NDZjODY4ZjM5YzFmZWE2YzYyNWJmOGE1M2ZjNzZmN2Y1ZGUwNGE3MmZkYzUwMTE0Y2Q1Zjk4NGE3MmI0M2YxNmU5NjgwYWY4OWZhZGRkZDMzOGIzMTQ3NDAzNjAwIiwiZXhwIjoiMTU5NTM1ODYwNyIsImlzcyI6IjB4MzA1NzRiNjU2NDQ4NmRlNDFjMzU0ODg3MzdiNzJlYjIyMzM4NmMwYyIsImp0aSI6ImEzNGE2Mjk5LTFjYzYtNDNjNi1iYWI1LTExMWNiMmJhNTAxMyIsIm5iZiI6IjE1OTUzNTUwMDciLCJzdWIiOiIweDMwNTc0YjY1NjQ0ODZkZTQxYzM1NDg4NzM3YjcyZWIyMjMzODZjMGMifQ.ovNWQUXszcarIBCG8muT4tKNCQlzZAPXMcUKYE81ljA5FQ1EQYsM-D126mo_V3D1g-duAb5bRzRsBmfIEN2QzA
nbf          1595355007
sub          0x30574b6564486de41c35488737b72eb223386c0c
```

The resultant `jwt` is the signed set of claims.

### Verify a set of claims

The `jwt` can be verified using the `verify` method on the plugin.

```sh
$ vault write -format=json immutability/sandbox/trust/verify token=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb21taXR0ZXIiOiJqcGxvdWdoIiwiZXRoIjoiMHg2ZmFkZjQxZjM1YjhkNmFmZDNkM2FmNzU2ZjRlNGU5NzRhNGMzYTU0M2M0OWVjYzU5NmE3ZjU3NmM4MzQxN2IxNWIxNTAwYmIyMDk0NGE4YTAzZTQ3YTMyODc4NWE4OTMwMzEwNTFjMjZiODJmMjFjYTQyYmRiNTE2MWY2NmVkMzAwIiwiZXhwIjoiMTU5NTM1NzkxNyIsImlzcyI6IjB4MmFkZjkzNmI3YjZmMzdlZTQzMTM1ZDViZDY5MDk1MDJjYzA5Yzc3MyIsImp0aSI6IjY2NWE4MjMzLTVlMWUtNGU5Mi1iYzAyLTAyNzQ5YThkNDJiOSIsIm5iZiI6IjE1OTUzNTQzMTciLCJzdWIiOiIweDJhZGY5MzZiN2I2ZjM3ZWU0MzEzNWQ1YmQ2OTA5NTAyY2MwOWM3NzMifQ.xbNPBhl_N0HV7U0Ou6pw6YrLCTcedDCTJkq55raiWVfyECeinzGBwRyXyFyHZ57C6cEqfmi5ykF22EMN1onFXg | jq .
{
  "request_id": "3b6a84a2-979d-0ab6-f5e4-b681a7f75117",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "watchmaker": "darwin",
    "eth": "0x6fadf41f35b8d6afd3d3af756f4e4e974a4c3a543c49ecc596a7f576c83417b15b1500bb20944a8a03e47a328785a893031051c26b82f21ca42bdb5161f66ed300",
    "exp": "1595357917",
    "iss": "0x2adf936b7b6f37ee43135d5bd6909502cc09c773",
    "jti": "665a8233-5e1e-4e92-bc02-02749a8d42b9",
    "nbf": "1595354317",
    "sub": "0x2adf936b7b6f37ee43135d5bd6909502cc09c773"
  },
  "warnings": null
}
```

The verify method returns the claims. If you trust the issuer `iss` of the Trustee tag, then you can trust the claims.

For example, in bad bash:

```sh
ISS=$(vault write -format=json immutability/sandbox/trust/verify token=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb21taXR0ZXIiOiJqcGxvdWdoIiwiZXRoIjoiMHg2ZmFkZjQxZjM1YjhkNmFmZDNkM2FmNzU2ZjRlNGU5NzRhNGMzYTU0M2M0OWVjYzU5NmE3ZjU3NmM4MzQxN2IxNWIxNTAwYmIyMDk0NGE4YTAzZTQ3YTMyODc4NWE4OTMwMzEwNTFjMjZiODJmMjFjYTQyYmRiNTE2MWY2NmVkMzAwIiwiZXhwIjoiMTU5NTM1NzkxNyIsImlzcyI6IjB4MmFkZjkzNmI3YjZmMzdlZTQzMTM1ZDViZDY5MDk1MDJjYzA5Yzc3MyIsImp0aSI6IjY2NWE4MjMzLTVlMWUtNGU5Mi1iYzAyLTAyNzQ5YThkNDJiOSIsIm5iZiI6IjE1OTUzNTQzMTciLCJzdWIiOiIweDJhZGY5MzZiN2I2ZjM3ZWU0MzEzNWQ1YmQ2OTA5NTAyY2MwOWM3NzMifQ.xbNPBhl_N0HV7U0Ou6pw6YrLCTcedDCTJkq55raiWVfyECeinzGBwRyXyFyHZ57C6cEqfmi5ykF22EMN1onFXg | jq -r .data.iss)

if [ $ISS = "0x2adf936b7b6f37ee43135d5bd6909502cc09c773" ]; then
    echo "I trust you"
fi
```

## More Flowery Prose

We live in a dynamic world. So does our software. As such, there are challenges for the security practioner. In the old days, services had well-known IP addresses and we could use knowledge of such things to design webs of trust: perhaps certain kinds of requests would only be trusted if they originated from a well-known IP address. Vault's AppRole authentication mechanism can work this way: we may not trust an application's use of credentials if they don't originate from the IP address range that we are expecting.

In our new world of containers as functions and micro-services, IP addresses are less well-known - at least with the kind of resolution that is necessary to make trust decisions. Furthermore, IP addresses have always been problematic as an authentication factor: it only works well if you have "true" IP - the protocols used by proxies are insecure as X-Forwarded-For can be tampered with; and, it isn't realistic to expect a packet to be relayed without some form of network address translation. Wouldn't it be awesome if there was a functional equivalent of the IP address for the modern Internet?

## Extending the IP Metaphor with Ethereum Addreses

There is another kind of address that has become ubiquitous of late: the Ethereum address. This `address` is a cryptographically derived sequence of bytes that represents a single ECDSA public key and is used to verify signatures made with that public key's corresponding private key. Here is an example of an Ethereum address:

```
0xc2c24827F9d72a294B143B4E1d0Ab5e111361DF3
```

Ethereum addresses are no more intimidating from UX perspective than an IPv6 address (`2001:0db8:85a3:0000:0000:8a2e:0370:7334`), so, from the perspective of managing access controls based on Ethereum addresses (vs. IPv6 addresses) we haven't introduced much - if any - complexity. That is, from an information management viewpoint, the effort to allow/disallow actions based on a set of Ethereum addresses is similar to the effort to do so with IPv6 addresses.

But how does this work? The source IP doesn't carry an Ethereum address, so how do we actually implement these controls?

### Verifying Signatures using Ethereum Addresses

Suppose there is a web service: it could be a smart contract in the Ethereum ecosystem, a lambda in AWS, or a container running in Kubernetes - it just doesn't matter. If this web service has control of a private key (specifically a secp256k1 private key) it can create a signature for some `data` as follows:

1. hash = keccak256(data)
2. signature = sign(hash, private_key)

The web service also has a corresponding public key for that private key, and it is from this public key that the Ethereum address is derived:

1. address = right(keccak256(public_key),20 bytes)

Now, if the web service (the sender) sends the following to another party, i.e., the recipient:

* data
* signature
* address

The recipient can derive a public key from these pieces of information and verify that the signature was "created" by that address:

1. hash = keccak256(data)
2. public_key = signature_to_public_key(hash, signature)
3. if address == public_key_to_address(public_key)

The above means that the recipient can be sure that the sender (the possessor of the private key) signed the message. We don't know, however, that this message wasn't hijacked by a malicious 3rd party.

### Tightening Up

If we enforce transport security, using TLSv3 for instance, we reduce the risk of hijack. We can also add additional information to the sender's payload to reduce the potential for hijack - we can enforce short TTLs for these messages such that the message that the sender sends is only valid for a short period of time. In order to do that, we build upon another widely used mechanism - the bearer token - in the form of JWTs. 

## The Vault Trustee Plugin

The Vault Trustee plugin shares some code with the [Vault Ethereum plugin](https://github.com/immutability-io/vault-ethereum) - but the purpose of the Trustee plugin is quite different than that of the Ethereum plugin. (At some point, I will create a shared toolkit that both leverage.) The Vault Trustee plugin is intended to be used to generate JWT tokens that can be used for authentication and authorization. It is designed to work hand-in-hand with the [Vault JWT-Auth plugin](https://github.com/immutability-io/jwt-auth) to deliver a delegated authentication mechanism for modern serverless and microservice ecosystems. That said, this plugin could be used in many other use cases. I will describe the API for the plugin here and refer to the external documentation for the delegated authentication use case.

### Overview

At its essence, this plugin allows an authenticated caller to make assertions using the standard JWT format: the authenticated caller generates a JWT that contains any number of assertions (called `claims`). The JWT contains the Ethereum address of the caller as the `issuer` of the token. The caller then would transmit the JWT to another party. This other party (the recipient) can verify that the signature is valid - using the issuer - and if the recipient **trusts** this address, then the recipient honors the claims.

![Trustee](./doc/trustee.png?raw=true "The Typical Trustee Flow")


For example, imagine an actor (not a Hollywood actor - though it could be a Hollywood actor, I am thinking of a participant in a system interaction.) This actor asserts that he/she/it is entitled to certain claims by signing a JSON encoded data structure that contains all the things (claims) that the the actor thinks they are entitled to. This JWT might look like this:

```json

{
  "exp": "1526159771",
  "iss": "0xc2c24827F9d72a294B143B4E1d0Ab5e111361DF3",
  "jti": "34b40d89-8443-4b67-9843-6e9b8ab44e50",
  "nbf": "1526156171",
  "aud": "0x940b157c34E3594033B69c27FeE2325A00e72C5f",
  "sub": "0xc2c24827F9d72a294B143B4E1d0Ab5e111361DF3",
  "usage": ["knight_rider","baywatch_babes"]
}
```

The actor then sends this JWT to another agency - e.g., a car rental agency. This agency already **knows** and **trusts** an identity known by the address `0xc2c24827F9d72a294B143B4E1d0Ab5e111361DF3`. This agency has the ability to honor claims made on a particular car known as `knight_rider`. The agency receives the JWT, verifies it and then allows `usage` of `knight_rider`.

### Trust Must be Pre-Established 

Duh, right? As indicated by the above use case, the trust by the car agency of `0xc2c24827F9d72a294B143B4E1d0Ab5e111361DF3` was established before the JWT was transmitted. In systems like this trust must be established beforehand. How this trust is established is discussed [elsewhere](https://github.com/immutability-io/jwt-auth) but since we are using standard mechanisms for verification of claims, trust can be pre-established in many ways. The Trustee plugin is a mechanism to make trustworthy claims; but, it is not an authentication/authorization mechanism.

## API

[The API documentation is still being developed](./API.md)


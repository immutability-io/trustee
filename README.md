# trustee

A Vault plugin that solves for trust in a decentralized way

## Overview

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

The API is [here](./API.md)


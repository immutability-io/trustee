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



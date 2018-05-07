# trustee

A Vault plugin that solves for trust in a decentralized way


## Super simple overview

The goal here is to take the incoming JWT - which is a *special* JWT - and use it to self-validate. The JWT was authored by this plugin, after all. We leverage basic ESDSA mechanics here.

The JWT should contain:

jwt["iss"] == ETH address of issuer
jwt["jti"] == nonce that was hashed and signed
jwt["eth"] == signature by issuer of hashed jti

We derive public key, PubKey, from the signature and the hash(jwt["jti"]). Then we derive the ETH address, EthAddr, from
PubKey. If jwt["iss"] == EthAddr, then we know that should attempt to validate the JWT with PubKey. If that works,
we know that EthAddr sent the claim. If we trust EthAddr, then we accept the claim.
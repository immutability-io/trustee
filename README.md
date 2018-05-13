# trustee

A Vault plugin that solves for trust in a decentralized way


## Overview

Imagine a land with many services: 

* Within a single enterprise, there may be many internal microservices (some more than micro - but to call them "fat" would be bullying) 
* Outside of the enterprise, there may be any number of services - remember the future (it's hard to remember something that hasn't happened yet) we have functions as a service everywhere

Now imagine an actor (not a Hollywood actor - though it could be a Hollywood actor, I am thinking of a participant in a system interaction.) This actor authenticates to an  identity providers, and this identity provider asserts that this actor is who he or she or it says it is. The identity provider does that by signing a JSON encoded data structure that contains all the things (claims) that the identity provider believes the actor is entitled to.

This JWT might look like this:

```json

{
  "exp": "1526159771",
  "iss": "0xc2c24827F9d72a294B143B4E1d0Ab5e111361DF3",
  "jti": "34b40d89-8443-4b67-9843-6e9b8ab44e50",
  "nbf": "1526156171",
  "aud": "0x940b157c34E3594033B69c27FeE2325A00e72C5f",
  "sub": "0x7D158b9b2e7cc73AE0A204303EC62f8Cf83Fe36D",
  "roles": ["knight_rider","baywatch_babes"]
}
```

### What the heck are these `0x` thingies?

The first thing that you might notice about this JWT is that there are 3 values starting with `0x`. These are a special kind of identifier: I will call them addresses, because that is what they are called in the Ethereum ecosystem. Ethereum addresses are sequences bytes (20) which are derived from the public key portion of an ECDSA keypair. They are derived using this algorithm: `address=right(keccak256(public_key),20)`.

While that may seem fairly opaque, the important thing to know is:

1. An Ethereum address corresponds to 1 public key; and,
2. A public key corresponds to 1 private key; and,
3. Whoever has access to private key is allowed to make cryptographic assertions.

Ok. That explanation isn't helping, is it? Let's try again.

### What is identity?

Before we talk about those `0x thingies, we need to talk about identity. What is it about you that make you unique? That is, what asserts your identity? Is it your DNA? Your blood or saliva or hair is an assertion of your identity, of course; but, it is pretty easy for someone to get a copy of your DNA (the maid in the hotel room, the bartender at your favorite nightspot, your dog who has stolen your underwear, ...) And, it would be awkard for someone to gain access to your bank account because they had a hair brush you forgot at a hotel... (Or that damn dog with your underwear...) 

Furthermore, what about things that have no DNA? Services, bots, lambdas, etc. These things have identities too - just not biological ones. Very often when we build systems, we need to know if a particular service makes an assertion.

So, in or modern digital landscape, identity can't be DNA. So, should an assertion about your identity be something only you (whatever you are) know? Some dearly held secret? This sounds a bit more practical: care canbe taken to safeguard that secret, and, if one so chooses, one can have different secrets for different contexts. Dearly held secrets in the form of cryptographic keys are what many folks use for identity assertions. It works like this:

1. IdentityX has a key (a secret) that only IdentityX can access - call this a private key;
2. This key has a pair that everyone can know - we call this the public key;
3. These 2 keys have special (nearly magical) mathematical properties that allow powerful kinds of assertions.

The assertions intimated by #3 above include the ability to say: if IdentityX is the only actor with access to a private key, then IdentityX is the only one who is allowed to make a certain kind of assertion:

**If I sign any statement with a private key, it can be proven incontrovertibly that I signed that statement**

#### The `0x` thingies represent identities

So, without spending much more time on public key cryptography, the point to be made is:

##### If I know your address (the `0x` thingie) I can verify that you made a statement.

And, while we know private keys can be stolen (and thus be used to make fraudulent assertions) it is really the best we can do right now.
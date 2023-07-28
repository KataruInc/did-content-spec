
## Introduction
`did:content` is identifies content such as images, video, and music. The goal is to be able to comprehensively decentralized manage content and rights

## Motivation
Recently, a wide variety of content uploaded on the Internet.
However, content identifiers depend on storage like a S3 / YouTube and so on, and if storage downs, access becomes difficult.
Naturally, there are solutions such as Contents Delivery Network(CDN) like Cloudflare / Fastly , but it must be said that they are still managed in a centralized.
In this method, the goal is to support content resolution and improve availability by defining IDs that can resolve various types of storage, etc., centered on content.
In addition, we aim to increase the number of users by extending the authentication of rights holders to two types, anonymous and non-anonymous, by using cryptographic methods.

## Status Of this document
This is a draft document

## Syntax and Interpretation

```
# Content DID
did:content:<method-specific-id>
```

```
did-content:   "did:content:" + content-id
content-id:    Base58(RIPEMD160(sha3-256(DID Document without id)))
```    

for examples:
```did
did:content:3qrgME9eV7brjYsx3Ebbp9hubiQna1wcD1FdzuG4P1V6xmZwSdLXzCG
```

Its corresponding DID document is as follows:
```
{
  "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://did.kataru.io/did/v1",
      "https://w3id.org/security/suites/secp256k1recovery-2020/v2"
  ],
  "id": "did:content:03Z5hdN7vxXyp5YW4WGqMYowMAB3SLG6tN2UjWb2DfAmkTHC1WYDfnjB",
  "controller": [
    "did:content:03Z5hdN7vxXyp5YW4WGqMYowMAB3SLG6tN2UjWb2DfAmkTHC1WYDfnjB#author",
    "did:content:03Z5hdN7vxXyp5YW4WGqMYowMAB3SLG6tN2UjWb2DfAmkTHC1WYDfnjB#rights-holder"
  ],
  "updation":["#keys-1", "#keys-2"],
  "verificationMethod": [
     {
        "id": "did:key:3TL4YbgfwnJmJhyxKKDRpA81vB1QkWvvWRMioKQb6yv9HYwsZCpnVWB#controller",
        "type": "EcdsaSecp256k1RecoveryMethod2020", 
        "controller": "did:key:3TL4YbgfwnJmJhyxKKDRpA81vB1QkWvvWRMioKQb6yv9HYwsZCpnVWB"
     },
     {
        "id": "did:key:3qrgME9eV7brjYsx3Ebbp9hubiQna1wcD1FdzuG4P1V6xmZwSdLXzCG#delegate",
        "type": "EcdsaSecp256k1RecoveryMethod2020", 
        "controller": "did:key:3qrgME9eV7brjYsx3Ebbp9hubiQna1wcD1FdzuG4P1V6xmZwSdLXzCG"
     }
  ],
  "authentication": ["#controller", "#delegate"],
  "assertionMethod": ["#controller", "#delegate"], 
  "service": [
    {
      "id": "#kataru",
      "type": "kataru",
      "serviceEndpoint": "https://kataru.io/content/mizuki"
    }
   ]
}
```

### Fragments
- `#author` if servive receive `#author` fragment, they should return authors of content
- `#rights-holder` if servive receive `#rights-holder` fragment, they should return rights-holder of content

## DID Operations

### Create　(Register)
Creating DID and DID Document for Holders is done through the following steps:

### Resolve (Read)


### Update (Replace)

### Deactive (Revoke)
    
## Security and Privacy Considerations

### Security
The following security considerations should be considered for the content DID method:
DID Resolver will check for authority with the sIgnature of the Controller recorded in the correct DID document. It is cryptographically more secure than existing authenticate methods (like password).
In addition, the `did:content` DID Resolver is OSS and can be built by anyone, allowing service providers to manage server root privileges.

### Privacy Considerations
The following privacy considerations should be considered for the content DID method:
In general, DID Docuement is for identifying an entity like content
DID content Resolver / DID document must not have Personally Identifiable Information (PII).

## Update History

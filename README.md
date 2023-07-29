
## Introduction
`did:content` is identifies content such as images, video, and music. The goal is to be able to comprehensively decentralized manage content and rights  

<img alt="overview" width="400" src="https://github.com/KataruInc/did-content-spec/assets/6281583/10c5b9f7-ea15-4b16-8839-4d1c5124b126" />  

Overview of `did:content` 

## Motivation
Recently, a wide variety of content uploaded on the Internet.　　 
However, content identifiers depend on storage like a S3 / YouTube. As a result, if storage downs, access becomes difficult.
Naturally, there are solutions such as Contents Delivery Network(CDN) like Cloudflare / Fastly, but it must be said that they are still managed in a centralized.  
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
  "updation":["#controller", "#delegate"],
  "authentication": ["#controller", "#delegate"],
  "assertionMethod": ["#controller", "#delegate"], 
  "service": [
    {
      "id": "#kataru",
      "type": "kataru",
      "serviceEndpoint": "https://kataru.io/content/mizuki"
    }
  ],
  "proof": {
    "type": "Secp256k1",
    "creator": "did:key:3qrgME9eV7brjYsx3Ebbp9hubiQna1wcD1FdzuG4P1V6xmZwSdLXzCG#key-1",
    "signatureValue": "0000fb29b515146a1633833c41c87fc902e3815394bf31d3d779172124fe653f100c07d99c1f485d34607765ec53c6c889b8c18dc477fa04e"
  }
}
```

### Fragments
- `#author` if servive receive `#author` fragment, they should return authors of content
- `#rights-holder` if servive receive `#rights-holder` fragment, they should return rights-holder of content

## DID Operations

### Create　(Register)
Creating DID and DID Document for Holders is done through the following steps:  
<img width="769" alt="create" src="https://github.com/KataruInc/did-content-spec/assets/6281583/11394201-85a8-4167-b2d6-f50b07d51cb1">  
The DID Document does not have a concrete property for content, and the DID and Content must be resolved on the External Service side.  
The DID Document contains information about the controllers who can control the content and the users who can view it.  
Note: [key generate code](https://github.com/KataruInc/did-content-spec/blob/main/app/id_gen.py)

### Resolve (Read)
Creating DID and DID Document for Holders is done through the following steps:   
<img width="960" alt="read" src="https://github.com/KataruInc/did-content-spec/assets/6281583/13936600-4a6a-4d20-9df1-c10b1cd4effd">  
Firstly, access the DID resolver, obtain a list of services in DID Document, access the external service that has the content, and obtain the contents.   
The external service side checks the authorization based on the controller information in the DID document and executes the request.    
(The Client may access the external service directly.)    
The service determines authorization based on the DID Document.    

### Update (Replace)
<img width="844" alt="update" src="https://github.com/KataruInc/did-content-spec/assets/6281583/b6a62472-5e28-464e-ae0d-5d9e79d6e63e">    
I expect updation is mainly used when   

- When updating a did document
- When changing the URL of Content　　
- When updating the Content delivery service    
  
### Deactive (Delete)
<img width="831" alt="delete" src="https://github.com/KataruInc/did-content-spec/assets/6281583/5ff771bb-de04-4782-868e-c1b672ef38c6">　　　　　

Delete is only for deleting DID documents,　    
Deletion of the content itself is optional.    
In other words, it only disables content resolution by DID.　    
　　
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
2023/07/28: release alpha version

## Copyright
@MizukiSonoko

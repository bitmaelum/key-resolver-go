
# Introdocution
This is the API documentation for the BitMaelum key resolver service. It contains all operations, input 
and output for communicating with the key resolver service.

This API is useful when creating your own BitMaelum client or tooling that needs to read or write addresses, 
organisations or routing information. 


## Authentication

All read operations (`GET` requests) can be done unauthenticated. Some write operations are only allowed when 
authenticated. For instance, when updating or deleting existing objects. Creating new objects can be added 
without authentication.

Authentication is done through sending a `Authentication` header field in the HTTP request. THis field consists
of the following:

    Authentication: BEARER <token>

The token depends on the kind of object:

### Address authentication

    sha256(hash of the address + routing ID of the address + serial number of the address)

All these fields can be retrieved by issuing a `GET` request on the address hash. These fields must be concatted together
(in the correct order), and run through the SHA256 hash function. 

The result of the hash function must be signed with the PRIVATE KEY of the address. The resulting signature must be  
base64 encoded and this will be the bearer token.

> Note that the retrieval of fields, and the actual post are two seperate requests and are thus not atomic. It might be 
> possible that another request in between already updated the object. In that case, the serial number of the object
> will have changed, and the token for your request will be invalid.

### Organisation authentication

Organisation authentication is needed for changing organisation data or (soft) deleting the organisation.

It works in the same way as address authentication, except it uses the following sha256 hash to be signed:

    sha256(hash of the organisation + serial number of the organisation)

### Routing authentication

Routing authentication is needed for changing routing data for a given mail server.

It works in the same way as address or organisation authentication, except it uses the following sha256 hash to be signed: 

    sha256(hash of the routing + serial number of the routing)


## Proof of work
In order to create a new organisation or address, you need to do proof-of-work. This proof will be checked when 
creating the organisation or address in the key resolver. The difficulty level of the proof-of-work depends on the key 
resolver and will gradually increase over time. To find the current difficulty level, you can get the config.json 
file of the key resolver by a `GET /config.json` (see below).

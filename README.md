<img alt="logo" align=right height=70 src="https://bitmaelum.com/logo_and_name.svg">

[![Go Report Card](https://goreportcard.com/badge/github.com/bitmaelum/key-resolver-go)](https://goreportcard.com/report/github.com/bitmaelum/key-resolver-go)
[![BitMaelum Key Resolver](https://github.com/bitmaelum/key-resolver-go/actions/workflows/ci.yml/badge.svg)](https://github.com/bitmaelum/key-resolver-go/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/bitmaelum/key-resolver-go/badge.svg?branch=master)](https://coveralls.io/github/bitmaelum/key-resolver-go?branch=master)
![License](https://img.shields.io/github/license/bitmaelum/key-resolver-go)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/bitmaelum/key-resolver-go)         
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=bitmaelum_bitmaelum-suite&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=bitmaelum_bitmaelum-suite)


<hr>

# Key resolver

This repository holds the (centralized) account and routing resolver for BitMaelum.

Its purpose is for users and mail servers to upload they public key and routing information. This will be used by 
clients and servers to find out the actual addresses to send mail to. Since we do not use domain names, we cannot 
leverage the DNS network. Another reason is that an account does not have to be located at the address of the 
organisation itself.

It works like this:

  - User uploads public key and routing id to their hash address.
  - Others can use a simple GET operation to fetch this information.
  - Changing or deleting must be done by adding a signature that proofs ownership of the private key.
  
The same goes for routing information:

  - Mail server uploads public key and routing id to their hash address.
  - Others can use a simple GET operation to fetch this information.
  - Changing or deleting must be done by adding a signature that proofs ownership of the private key.

The same goes for organisation information:

  - User uploads public key for their organisation.
  - Others can use a simple GET operation to fetch this information.
  - Changing or deleting must be done by adding a signature that proofs ownership of the private key.


Note that the keyserver does NOT hold any account information or messages. It only keeps track of public 
keys and routing information. Even bitmaelum addresses are not found on this service: only hashes are. 

This system is deployed to AWS where it runs as a single lambda behind an API gateway. The datastore is 
currently DynamoDB.


This system is the first step. It's centralised system means that one single entity (namely: us) are 
 in full control of address creation and even mutation. In order to truly become a decentralized system, 
 we need to figure out how to create a key resolver that:

  - Cannot be managed from a single point
  - Every node is equal (peer) and there are no servers or centralized storage
  - Allows users to add keys which are automatically redistributed throughout the key resolver network.
  - Collisions of same accounts must be handled (a user adding a key which already exists)
  
Some initial ideas are available [on the wiki](https://github.com/bitmaelum/key-resolver-go/wiki/Key-server-DHT)

![https://bitmaelum.com/logo_and_name.svg](https://bitmaelum.com/logo_and_name.svg)

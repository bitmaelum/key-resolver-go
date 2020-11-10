    
         ____  _ _   __  __            _                 
        |  _ \(_) | |  \/  |          | |                
        | |_) |_| |_| \  / | __ _  ___| |_   _ _ __ ___  
        |  _ <| | __| |\/| |/ _` |/ _ \ | | | | '_ ` _ \ 
        | |_) | | |_| |  | | (_| |  __/ | |_| | | | | | |
        |____/|_|\__|_|  |_|\__,_|\___|_|\__,_|_| |_| |_|
           P r i v a c y   i s   y o u r s   a g a i n                                          

# Key resolver

[![codecov](https://codecov.io/gh/bitmaelum/key-resolver-go/branch/develop/graph/badge.svg?token=IHXRZZO8KQ)](undefined)

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

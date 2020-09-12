    
         ____  _ _   __  __            _                 
        |  _ \(_) | |  \/  |          | |                
        | |_) |_| |_| \  / | __ _  ___| |_   _ _ __ ___  
        |  _ <| | __| |\/| |/ _` |/ _ \ | | | | '_ ` _ \ 
        | |_) | | |_| |  | | (_| |  __/ | |_| | | | | | |
        |____/|_|\__|_|  |_|\__,_|\___|_|\__,_|_| |_| |_|
           P r i v a c y   i s   y o u r s   a g a i n                                          

# Key resolver

This repository holds the (centralized) key resolver for BitMaeleum.

It's purposes is for users to upload they public key and routing information. This will be used by clients 
and servers to find out the actual addresses to send mail to. Since we do not use domain names, we cannot 
leverage the DNS network. Another reason is that an acount does not have to be located at the address of the 
organisation itself.

It works like this:

  - User uploads public key and routing info to their hash address.
  - Others can use a simple GET operation to fetch this information.
  - Changing or deleting must be done by adding a signature that proofs ownership of the private key.

Note that the keyserver does NOT hold any account information or messages. It only keeps track of public 
keys and routing information. Even bitmaelum addresses are not found: only hashes are used. 

This system is deployed to AWS where it runs as a single lambda behind an API gateway. The datastore is 
currently DynamoDB.


This system is the first step. It's centralised system means that one single entity (namely: us) are 
 in full control of address creation and even mutation. In order to truly become a decentralized system, 
 we need to figure out how to create a key resolver that:

  - Cannot be managed from a single point
  - Every node is equal (peer) and there are no servers or centralized storage
  - Allows users to add keys which are automatically redistributed throughout the key resolver network.
  - Collisions of same accounts must be handled (a user adding a key that already exist)

![https://bitmaelum.com/logo_and_name.svg](https://bitmaelum.com/logo_and_name.svg)

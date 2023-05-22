# Secure-Internet-Poker
A simplified version of a poker game using client-server architecture and secure cryptographic protocols

## Programming Language
Python 3.11.2

## Dependencies
This program relies on PyCryptodomeX to ensure secure communication between client and server.  
If not already installed, please install PyCryptodomeX
```pip install PyCryptodomeX```

## How to run server
To run the server you must first navigate to ```.\Secure-Internet-Poker\server``` before running the server program.  
From the home directory run ```cd .\server```  
  
The format for running the server is as follows:  
```
python3 server.py SERVER_IP SERVER_PORT
or
python server.py SERVER_IP SERVER_PORT
```  

Where SERVER_IP is a valid ip or hostname and SERVER_PORT is a valid port (including 0 for an ephemeral port)  
  
Examples
```
python3 server.py 127.0.0.1 1234
python3 server.py localhost 0
```

## How to run client
To the client you must first navigate to ```.\Secure-Internet-Poker\clients```. From the home directory run ```cd .\clients```. *Note* that the client program will need to be run on different terminals, seperate from each other and the server.  

The format for running the server is as follows:  
```
python3 client.py IDENTITY DS_SCHEME SERVER_IP SERVER_PORT
or
python client.py IDENTITY DS_SCHEME SERVER_IP SERVER_PORT
```

Where IDENTITY is either 1 or 2, DS_SCHEME is either RSA or DSA, SERVER_PORT is a valid port (including 0 for an ephemeral port).  

Examples
```
python3 client.py 1 RSA 127.0.0.1 1234
python3 client.py 2 DSA localhost 1234
```

## How to play

In this poker game each player is given 3 random cards. For three rounds players will choose a card from their hand. The player with the higher card wins the round. The player with the most wins at the end of the third round wins, or else it is a draw.

## Security

This game is made secure through both Public Key Cryptography and Symmetric Cryptography. In this implementation it is assumed that public keys have already been distributed securely among server and clients.

### Public Key Cryptography

The **Server** uses 2048-bit RSA keys to provide digital signature. Digital Signatures are generated using SHA256 hashes. See ```mydigitalsignature.py``` for the generation and verification of digital signatures. Additionally, the server uses its RSA key for securely exchanging session keys between client and server. Before the session key is formally used a challenge response is performed. See ```Client.send_hello()``` and ```Client.challenge_response()``` in client.py and ```Server.accept_players()``` in server.py for specific details on session key exhange.
  
**Clients** have the choice of either using a 2048-bit RSA or DSA key for digital signing. Again, see ```mydigitalsignature.py``` for more details on digital signing.

### Symmetric Cryptography

After key exchange between the client and server, the 128-bit session key is used to both encrypt and decrypt messages on both sides. Before The chosen cipher for encryption/decryption is AES with GCM block cipher mode. See ```message.py``` for specific details on how messages are formulated and encrypted/decryped.

## Closing remarks

I hope you enjoyed my Secure Internet Poker Game! PLEASE, if possible give feedback via pull request comments, it would mean a lot to me!
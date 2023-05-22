# Secure-Internet-Poker
A simplified version of a poker game using client-server architecture and secure cryptographic protocols

## Programming Language
Python 3.11.2

## Dependencies
This program relies on PyCryptodomeX to ensure secure communication between client and server.  
If not already installed, please install PyCryptodomeX
```pip install PyCryptodomeX```

## How to run server
To run the server you must first navigate to ```.\Secure-Internet-Poker\server``` before running the server program  
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
To the client you must first navigate to ```.\Secure-Internet-Poker\clients``` before running the server program  
From the home directory run ```cd .\clients```  

The format for running the server is as follows:  
```
python3 client.py IDENTITY DS_SCHEME SERVER_IP SERVER_PORT
or
python client.py IDENTITY DS_SCHEME SERVER_IP SERVER_PORT
```

Where IDENTITY is either 1 or 2, DS_SCHEME is either RSA or DSA, SERVER_PORT is a valid port (including 0 for an ephemeral port)  

Examples
```
python3 client.py 1 RSA 127.0.0.1 1234
python3 client.py 2 DSA localhost 1234
```
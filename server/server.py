import socket
import ipaddress
import sys
import struct
from pathlib import Path

from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.Hash import SHA256, SHA512, SHA1

sys.path.append('..')
from mydigitalsignature import DigitalSignature as DS

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Server:
    def __init__(self, server_ip, server_port):
        self.ip = server_ip
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, server_port))
        self.port = self.socket.getsockname()[1]

    
        self.private_key = RSA.import_key(Path('server_rsa_private_key.pem').read_bytes())
        self.public_keys = {
            (1, 'RSA'): RSA.import_key(Path('player1_rsa_public_key.pem').read_bytes()),
            (2, 'RSA'): RSA.import_key(Path('player2_rsa_public_key.pem').read_bytes()),
            (1, 'DSA'): DSA.import_key(Path('player1_dsa_public_key.pem').read_bytes()),
            (2, 'DSA'): DSA.import_key(Path('player2_dsa_public_key.pem').read_bytes())
        }
        self.rsa_cipher = PKCS1_OAEP.new(self.private_key)

        self.clients = {}

    def start(self):
        
        # Accept client connections until player1 and player2 connect
        self.socket.listen(2)
        print(f'Listening for connections on {self.ip}:{self.port}\n')
        while len(self.clients) < 2:

            # Wait for a client to connect
            conn, addr = self.socket.accept()

            # Client connected 
            print(f'Client connected from {addr}')

            # Recieve client message and obtain session key ######################################
            client_message_enc = conn.recv(1024)
            ciphertext, signature = client_message_enc[:256], client_message_enc[256:]

            # Decrypt ciphertext
            plaintext = self.rsa_cipher.decrypt(ciphertext)

            # Parse plaintext
            identity, signature_scheme, session_key = struct.unpack('I 3s 32s', plaintext)
            public_key = self.public_keys[(identity, signature_scheme.decode('utf-8'))]

            # Verify digital signature
            try: DS.verify_digital_signature(SHA1.new(plaintext), signature, public_key)
            except ValueError:
                print(f'{bcolors.FAIL}Could not verify digital signature{bcolors.ENDC}')
                Server.close_client_connection(conn, addr)
                continue

            # Add client to client dictionary
            if identity not in self.clients:
                self.clients[identity] = (session_key, public_key)
                print(f'{bcolors.OKGREEN}Player{identity} has connected!{bcolors.ENDC}\n')
            else:
                print(f'{bcolors.WARNING}Player{identity} already connected...{bcolors.ENDC}')
                Server.close_client_connection(conn, addr)

    @staticmethod
    def close_client_connection(conn, addr):
        print(f'Closing client connection at {addr}\n')
        conn.close()


if __name__ == '__main__':

    print()

    # Ensure correct number of parameters ########################################################
    if len(sys.argv) != 3:
        print('Usage: python server.py SERVER_IP SERVER_PORT\n')
        exit(1)

    # Parse SERVER_IP as IP address
    try: ip = ipaddress.ip_address(sys.argv[1])
    except ValueError:
        # Try parsing as hostname
        try:
            ip_string = socket.gethostbyname(sys.argv[1])
            ip = ipaddress.ip_address(ip_string)
        except socket.gaierror:
            print('Invalid server ip address\n')
            exit(1)

    # Parse SERVER_PORT
    try: port = int(sys.argv[2])
    except ValueError:
        print('Invalid port number\n')
        exit(1)
    if port < 0 or port > 65535:
        print('Invalid port number\n')
        exit(1)

    server = Server(ip.compressed, port)
    server.start()
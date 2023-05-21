import socket
import sys

from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.Hash import SHA512, SHA256, SHA1
from Cryptodome.Random import get_random_bytes


from pathlib import Path
import ipaddress
import struct

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

class Client:

    def __init__(self, player_num, hash, server_ip, server_port):
        '''

        Parameters -
            player_num (int): identity of player (1 or 2)
            hash (str): name of the hash used for digital signing (RSA or DSA)
            server_ip (str): the ip address of the server
            server_port (int): the port number of the server
        '''

        self.player_num = player_num
        self.hash_name = hash

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip, self.port = server_ip, server_port

        self.session_key = get_random_bytes(32)
        self.aes_cipher = AES.new(self.session_key, AES.MODE_GCM)

 
        self.private_key = RSA.import_key(Path(f'player{player_num}/player{player_num}_rsa_private_key.pem').read_bytes()) if hash == 'RSA' else \
            DSA.import_key(Path(f'player{player_num}/player{player_num}_dsa_private_key.pem').read_bytes())
        self.server_key = RSA.import_key(Path(f'player{player_num}/server_rsa_public_key.pem').read_bytes())
        self.rsa_cipher_server = PKCS1_OAEP.new(self.server_key)

    def start(self):

        # Try to connect the server ##############################################################
        # Terminate the client upon failure to connect ###########################################
        try:
            print(f'Connecting to server at {self.ip}:{self.port}')
            self.server_socket.connect((self.ip, self.port))
        except ConnectionRefusedError:
            self.close_client(f'{bcolors.FAIL}FAILED TO CONNECT!{bcolors.ENDC}\n')

        print(f'{bcolors.OKGREEN}Success!!!{bcolors.ENDC}\n')

        # Send hello message to server containing identity, hash, and session key ################
        # Terminate client if connection closes or fails
        try:
            # Create message
            plaintext = struct.pack('I 3s 32s', self.player_num, self.hash_name.encode('utf-8'), self.session_key)

            # Get digital signature
            signature = DS.generate_digital_signature(SHA1.new(plaintext), self.private_key)

            # Encrypt plaintext
            ciphertext = self.rsa_cipher_server.encrypt(plaintext)

            # Send ciphertext and digital signature to server
            self.server_socket.send(ciphertext + signature)
        except ConnectionError:
            self.close_client(f'{bcolors.WARNING}Error: Could not send data!!!')

        #
        self.close_client(f'{bcolors.OKGREEN}Have A Nice Day!!!{bcolors.ENDC}')
    
    def close_client(self, message):
        print(f'{message}\nClosing client . . .\n\n\n\n')
        self.server_socket.close()
        exit(1)



        

if __name__ == '__main__':

    print()

    # Ensure correct number of parameters ########################################################
    if len(sys.argv) != 5:
        print('Usage: python client.py PLAYER_NUMBER DGST_SCHEME SERVER_IP SERVER_PORT\n')
        exit(1)

    # Parse PLAYER_NUMBER ########################################################################
    try: 
        num = int(sys.argv[1])
        if num not in (1, 2):
            raise ValueError
    except ValueError:
        print('Invalid player number (accepts 1 or 2)\n')
        exit(1)

    # Parse DGST_SCHEME ##########################################################################
    if sys.argv[2].upper() not in ('RSA', 'DSA'):
        print("Invalid digital signature scheme (accepts 'RSA' or 'DSA')\n")
        exit(1)
    hash = sys.argv[2].upper()

    # Parse SERVER_IP as IP address ##############################################################
    try: ip = ipaddress.ip_address(sys.argv[3])
    except ValueError:
        # Try parsing as hostname 
        try:
            ip_string = socket.gethostbyname(sys.argv[3])
            ip = ipaddress.ip_address(ip_string)
        except socket.gaierror:
            print('Invalid server ip address\n')
            exit(1)

    # Parse SERVER_PORT ##########################################################################
    try: port = int(sys.argv[4])
    except ValueError:
        print('Invalid port number\n')
        exit(1)
    if port < 0 or port > 65535:
        print('Invalid port number\n')
        exit(1)

    # Create Client ##############################################################################
    player = Client(num, hash, ip.compressed, port)

    # Start Client ###############################################################################
    player.start()

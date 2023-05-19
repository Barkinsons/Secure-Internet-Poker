import socket
import sys

from Cryptodome.PublicKey import RSA
from pathlib import Path
import ipaddress

class Client:

    def __init__(self, player_num, server_ip, server_port):
        self.player_num = player_num
        self.private_key = RSA.import_key(Path(f'player{player_num}/player{player_num}_private_key.pem').read_bytes())
        self.server_key = RSA.import_key(Path(f'player{player_num}/server_public_key.pem').read_bytes())

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip, self.port = server_ip, server_port

    def start(self):

        # Try to connect the server 
        try:
            print(f'Connecting to server at {self.ip}:{self.port}')
            self.server_socket.connect((self.ip, self.port))
        except ConnectionRefusedError:
            print(f'Could not connect to the server at {self.ip}:{self.port}')
        

if __name__ == '__main__':

    print()

    # Ensure correct number of parameters
    if len(sys.argv) != 4:
        print('Usage: python client.py PLAYER_NUMBER SERVER_IP SERVER_PORT\n')
        exit(1)

    # Parse PLAYER_NUMBER
    try: 
        num = int(sys.argv[1])
        if num not in (1, 2):
            raise ValueError
    except ValueError:
        print('Invalid player number\n')
        exit(1)

    # Parse SERVER_IP as IP address
    try: ip = ipaddress.ip_address(sys.argv[2])
    except ValueError:
        # Try parsing as hostname
        try:
            ip_string = socket.gethostbyname(sys.argv[2])
            ip = ipaddress.ip_address(ip_string)
        except socket.gaierror:
            print('Invalid server ip address\n')
            exit(1)

    # Parse SERVER_PORT
    try: port = int(sys.argv[3])
    except ValueError:
        print('Invalid port number\n')
        exit(1)

    # Create Client 
    player = Client(num, ip.compressed, port)

    # Start Client
    player.start()

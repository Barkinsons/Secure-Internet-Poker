import socket
import sys

from Cryptodome.PublicKey import RSA
from pathlib import Path

class Client:

    def __init__(self, player_num):
        self.player_num = player_num
        self.private_key = RSA.import_key(Path(f'player{player_num}/player{player_num}_private_key.pem').read_bytes())
        self.server_key = RSA.import_key(Path(f'player{player_num}/server_public_key.pem').read_bytes())
        

if __name__ == '__main__':

    # Ensure correct parameters
    if len(sys.argv) != 2 or not sys.argv[1].isnumeric():
        print('Usage: python client.py PLAYER_NUMBER')
        exit(1)

    # Ensure player number is 1 or 2
    if int(sys.argv[1]) not in (1, 2):
        print('Invalid player number. . .\n')
        exit(1)

    player = Client(int(sys.argv[1]))
import socket
import ipaddress
import sys
import struct
from pathlib import Path
from random import randint
import threading
from time import sleep

from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.Hash import SHA256, SHA512, SHA1

sys.path.append('..')
from mydigitalsignature import DigitalSignature as DS
from message import Message as M

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
        self.player1_score = 0

    def start(self):
        
        # Wait for players 1 and 2 to join
        self.accept_players()
        
        # Both players have joined
        player1_conn, player1_session_key, player1_public_key = self.clients[1]
        player2_conn, player2_session_key, player2_public_key = self.clients[2]
        # print(player1_session_key)
        # print()
        # print(player2_session_key)

        # Create aes encryption objects
        player1_cipher = AES.new(player1_session_key, AES.MODE_GCM)
        player2_cipher = AES.new(player2_session_key, AES.MODE_GCM)

        # Start the poker game ###################################################################

        # Create player hands
        player1_hand = [randint(1, 15) for _ in range(3)]
        player2_hand = [randint(1, 15) for _ in range(3)]

        # Distribute player hands
        try:
            M.send(player1_conn, player1_session_key, self.private_key, 'I I I', *player1_hand)
            M.send(player2_conn, player2_session_key, self.private_key, 'I I I', *player2_hand)
        except socket.error:
            self.close_server(f'{bcolors.FAIL}Error: could not send player hands{bcolors.ENDC}',
                              player1_conn, player2_conn)

        for _ in range(2):

            # Receive player move choice
            try:
                player1_card = M.get(player1_conn, player1_session_key, player1_public_key, 'I', 4)[0]
                player2_card = M.get(player2_conn, player2_session_key, player2_public_key, 'I', 4)[0]

            except ValueError:
                self.close_server(f'{bcolors.FAIL}Error: could not verify digital signature{bcolors.ENDC}',
                                  player1_conn, player2_conn)
            except socket.error:
                self.close_server(f'{bcolors.FAIL}Error: could not received player cards{bcolors.ENDC}',
                                  player1_conn, player2_conn)

            # Print player cards
            print(f'Player1 chose {player1_card} - {player1_hand}')
            print(f'Player2 chose {player2_card} - {player2_hand}\n')

            # Validate choice
            if player1_card not in player1_hand or player2_card not in player2_hand:
                self.close_server(f'{bcolors.FAIL}Error: player card not in hand{bcolors.ENDC}',
                                  player1_conn, player2_conn)

            # Update player hand
            player1_hand.remove(player1_card)
            player2_hand.remove(player2_card)

            # Determine winner
            if player1_card == player2_card:
                result = 0
            elif player1_card > player2_card:
                result = 1
                self.player1_score += 1
            else:
                result = 2
                self.player1_score -= 1

            # Print result
            print(f'{bcolors.OKCYAN}Player{result} Wins!{bcolors.ENDC}\n') if result != 0 else \
                print(f"{bcolors.OKCYAN}It's a Tie!!{bcolors.ENDC}\n")

            # Send result and choice to players
            M.send(player1_conn, player1_session_key, self.private_key, 'I I I', player1_card, player2_card, result)
            M.send(player2_conn, player2_session_key, self.private_key, 'I I I', player2_card, player1_card, result)

        player1_card = player1_hand[0]
        player2_card = player2_hand[0]

        # Decide winner
        if player1_card < player2_card:
            result = 2
        elif player1_card > player2_card:
            result = 1
            self.player1_score += 1
        else:
            result = 0
            self.player1_score -= 1

        print(f"Player1's last card is {player1_card} - {player1_hand}")
        print(f"Player2's last card is {player2_card} - {player2_hand}\n")

        print(f'{bcolors.OKCYAN}Player{result} Wins!{bcolors.ENDC}\n') if result != 0 else \
                print(f"{bcolors.OKCYAN}It's a Tie!!{bcolors.ENDC}\n")
        

        # Send result and choice to players
        M.send(player1_conn, player1_session_key, self.private_key, 'I I I', player1_card, player2_card, result)
        M.send(player2_conn, player2_session_key, self.private_key, 'I I I', player2_card, player1_card, result)

        if self.player1_score < 0:
            print(f'{bcolors.OKGREEN}PLAYER2 WINS!!!{bcolors.ENDC}\n')
        elif self.player1_score > 0:
            print(f'{bcolors.OKGREEN}PLAYER1 WINS!!!{bcolors.ENDC}\n')
        else:
            print(f"{bcolors.OKCYAN}THE GAME IS A DRAW!{bcolors.ENDC}\n")

        self.close_server('', player1_conn, player2_conn)

    def accept_players(self):
        '''Accept client connections until player1 and player2 connect'''

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
            identity, signature_scheme, session_key = struct.unpack('I 3s 16s', plaintext)
            public_key = self.public_keys[(identity, signature_scheme.decode('utf-8'))]

            # Verify digital signature
            try: DS.verify_digital_signature(SHA1.new(plaintext), signature, public_key)
            except ValueError:
                print(f'{bcolors.FAIL}Could not verify digital signature{bcolors.ENDC}')
                Server.close_client_connection(conn)
                continue

            # Add client to client dictionary
            if identity not in self.clients:
                self.clients[identity] = (conn, session_key, public_key)
                print(f'{bcolors.OKGREEN}Player{identity} has connected!{bcolors.ENDC}\n')
            else:
                print(f'{bcolors.WARNING}Player{identity} already connected{bcolors.ENDC}')
                Server.close_client_connection(conn)

    def send_hand(self, hand, cipher, connection):

        # Create message
        plaintext = struct.pack('I I I', *hand)

        # Create digital signature
        signature = DS.generate_digital_signature(SHA1.new(plaintext), self.private_key)

        # Encrypt plaintext
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Send message over connection
        connection.send(cipher.nonce + tag + ciphertext + signature)

    def get_card(self, connection, session_key):

        # Receive message
        message = connection.recv(1024)
        nonce, tag, ciphertext, signature = message[:16], message[16:32], message[32:36], message[36:]

        # Create aes object for decryption
        cipher = AES.new(session_key, AES.MODE_GCM, nonce)

        # Decrypt ciphertext
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # Return card choice
        return struct.pack('I', plaintext)

    def close_server(self, message, player1_conn, player2_conn):

        print(f'{message}\nClosing server...')

        try: player1_conn.close()
        except socket.error: print(f'{bcolors.WARNING}Player1 connection already closed{bcolors.ENDC}')
        else: print('Player1 connection closed...')

        try: player2_conn.close()
        except socket.error: print(f'{bcolors.WARNING}Player2 connection already closed{bcolors.ENDC}')
        else: print('Player2 connection closed...')

        try: self.socket.close()
        except socket.error: print(f'{bcolors.FAIL}Could not close server connection{bcolors.ENDC}\n')
        else: print('Server connection closed\n')

        print(f'{bcolors.OKGREEN}Have A Good Day!!!{bcolors.ENDC}\n\n\n')
        exit(1)

    @staticmethod
    def close_client_connection(conn, number=''):
        conn.close()
        print(f'Closing client{number} connection...\n')


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
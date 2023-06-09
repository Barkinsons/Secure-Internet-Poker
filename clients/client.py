##########################################################################
# client.py - Client program for Secure Internet Poker Game              #
# Copyright (C) 2023 Jared Sevilla                                       #
#                                                                        #
# This program is free software: you can redistribute it and/or modify   #
# it under the terms of the GNU General Public License as published by   #
# the Free Software Foundation, either version 3 of the License, or      #
# (at your option) any later version.                                    #
#                                                                        #
# This program is distributed in the hope that it will be useful,        #
# but WITHOUT ANY WARRANTY; without even the implied warranty of         #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          #
# GNU General Public License for more details.                           #
#                                                                        #
# You should have received a copy of the GNU General Public License      #
# along with this program.  If not, see <https://www.gnu.org/licenses/>. #
##########################################################################

from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA1
from Cryptodome.Random import get_random_bytes

from random import randint
from pathlib import Path
import ipaddress
import socket
import struct
import sys

sys.path.append('..')
from mydigitalsignature import DigitalSignature as DS
from message import Message as M


class bcolors:
    '''
    Class for holding ANSI escape sequences
    
    taken from https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal
    '''

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
    '''
    Client for Secure Internet Poker Game

    Attributes -
        General -
            player_num (int): the identity of the player (1 or 2)
            hash (str): name of the hash used for digital signing (RSA or DSA)
            
        Game -
            score (int): the current score of the client
            hand (tuple): the current hand
            card (int): the current chosen card

        Server - 
            server_socket (socket.socket): the TCP socket used for communication with server
            server_ip (str): the ip address of the server
            server_port (int): the port number of the server

        Symmetric Cryptography -
            session_key (bytes): the 16-byte session key used for secure communication with server

        Public Key Cryptography -
            private_key (Rsa.Key | Dsa,key): the private key used for digital signing
            server_key (Rsa.Key): the public key used for digital signature verification
            rsa_cipher_server (PKCS1_OAEP.PKCS1OAEP_Cipher): the cipher used for assymmetric encryption

    Methods -
        start_game():
            Start the Secure Internet Poker Game

        send_hello():
            Send hello message to server

        challenge_response()
            Do challenge response protocol

        get_cards_and_result():
            Get and validate cards and result from server

        close_client(message):
            Close the client and exit program
    '''

    def __init__(self, player_num: int, hash: str, server_ip: str, server_port: int) -> None:
        '''

        Parameters -
            player_num (int): identity of player (1 or 2)
            hash (str): name of the hash used for digital signing (RSA or DSA)
            server_ip (str): the ip address of the server
            server_port (int): the port number of the server
        '''

        # General Attributes
        self.player_num = player_num
        self.hash_name = hash

        # Game Attributes
        self.score = 0
        self.hand = self.card = None

        # Server Attributes
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip, self.port = server_ip, server_port

        # Symmetric Cryptography Attributes
        self.session_key = get_random_bytes(16)

        # Public Key Cryptography Attributes
        self.private_key = RSA.import_key(Path(f'player{player_num}/player{player_num}_rsa_private_key.pem').read_bytes()) if hash == 'RSA' else \
            DSA.import_key(Path(f'player{player_num}/player{player_num}_dsa_private_key.pem').read_bytes())
        self.server_key = RSA.import_key(Path(f'player{player_num}/server_rsa_public_key.pem').read_bytes())
        self.rsa_cipher_server = PKCS1_OAEP.new(self.server_key)

    def start_game(self) -> None:
        '''
        Start the Secure Internet Poker Game
        
        Steps:
            1. Connect to the server
            2. Send hello message and perform challenge response
            3. Get player hand
            4. Chose card from hand
            5. Send card to server
            6. Get and print cards and result
            7. Repeat steps 4-6 for another 3 rounds (-5 for last round)
            8. Print final result
            9. End the game
        '''
        ### CONNECT TO THE SERVER ##########################################################################
        try:
            print(f'Connecting to server at {self.ip}:{self.port}')
            self.server_socket.connect((self.ip, self.port))
        except ConnectionRefusedError:
            self.close_client(f'{bcolors.FAIL}FAILED TO CONNECT!{bcolors.ENDC}')

        print('Connected...\n')

        ####################################################################################################

        ### SEND HELLO MESSAGE AND PERFORM CHALLENGE RESPONSE ##############################################
        self.send_hello()
        self.challenge_response()
        print(f'{bcolors.OKGREEN}Success!!!{bcolors.ENDC}\n')
        
        ####################################################################################################

        ### GET PLAYER HAND ################################################################################
        try: self.hand = list(M.get(self.server_socket, self.session_key, self.server_key, 'I I I', 12))
        except struct.error:
            self.close_client(f'{bcolors.FAIL}Error: Could not get player hand...{bcolors.ENDC}\
                              \nPlayer{self.player_num} may have already joined...\
                              \nEnsure correct parameters before trying again.')

        ####################################################################################################

        # Steps 4-7 thrice
        #== LOOP STARTS HERE ===============================================================================
        for i in range(3):

            # Print round string
            print(f'{bcolors.BOLD}==================== ROUND {i+1} ===================={bcolors.ENDC}\n')

            ### CHOOSE CARD FROM HAND ######################################################################
            # Rounds 1 and 2
            if i < 2:
                print('Please choose a card from your current hand:')
                
                # Continue until correct value is chosen
                while True:
                    print(f'\tCurrent hand: {self.hand}')

                    # Get card input
                    card = input('Choice: ')

                    if not card.isnumeric() or int(card) not in self.hand:
                        print(f'{card} not in hand, please try again...\n')
                        continue
                    else:
                        self.card = int(card)
                        break

                # Remove card from current hand
                self.hand.remove(self.card)

                ############################################################################################

                ### SEND CARD TO SERVER ####################################################################
                try: M.send(self.server_socket, self.session_key, self.private_key, 'I', self.card)
                except socket.error:
                    self.close_client(f'{bcolors.FAIL}Error: could not send card{bcolors.ENDC}')

                # print waiting message
                print('Waiting for player1...\n') if self.player_num == 2 else print('Waiting for player2...\n') 

                ############################################################################################

            # Round 3
            else:
                # last card
                self.card = self.hand[0]

            ### GET AND PRINT CARDS AND RESULT #############################################################
            my_card, opponent_card, result = self.get_cards_and_result()

            # CARDS
            # Last round
            if i == 2:
                print(f'Your last card: {self.card}')
                print(f"Their last card: {opponent_card}")

            # First two rounds
            else:
                print(f'You chose {my_card}')
                print(f'They chose {opponent_card}')

            # RESULT
            if result == 0:
                # print tie
                print(f"{bcolors.OKCYAN}It's a Tie!!{bcolors.ENDC}\n")

            elif result == self.player_num:
                # print win and increment score
                print(f'{bcolors.OKGREEN}You won the round!!!{bcolors.ENDC}\n')
                self.score += 1

            else:
                # print loss and decrement score
                print(f'{bcolors.FAIL}You lost the round.{bcolors.ENDC}\n')
                self.score -= 1
        
            ################################################################################################

        #== LOOP ENDS HERE =================================================================================

        print(f'{bcolors.BOLD}================================================={bcolors.ENDC}\n')

        ### PRINT FINAL RESULT #############################################################################
        if self.score == 0:
            print(f'{bcolors.OKCYAN}{bcolors.BOLD}{bcolors.UNDERLINE}THE GAME WAS A TIE!{bcolors.ENDC}\n')
        elif self.score > 0:
            print(f'{bcolors.OKGREEN}{bcolors.BOLD}{bcolors.UNDERLINE}YOU WON THE GAME!!!{bcolors.ENDC}\n')
        else:
            print(f'{bcolors.FAIL}{bcolors.BOLD}{bcolors.UNDERLINE}You lost the game...{bcolors.ENDC}\n')

        ### END THE GAME ###################################################################################
        self.close_client(f'{bcolors.BOLD}Have A Nice Day!!!{bcolors.ENDC}')

    def send_hello(self) -> None:
        '''
        Send hello message to server
        
        The hello message contains the identity of the client, the 
        hash chosen for digital signing and signature verification, 
        and the session key for further encryption and decryption

        This function will call close_client if communication with
        the server fails
        '''

        try:
            # Create message
            plaintext = struct.pack('I 3s 16s', self.player_num, self.hash_name.encode('utf-8'), self.session_key)

            # Create digital signature
            signature = DS.generate_digital_signature(SHA1.new(plaintext), self.private_key)

            # Encrypt plaintext
            ciphertext = self.rsa_cipher_server.encrypt(plaintext)

            # Send ciphertext and digital signature to server
            self.server_socket.send(ciphertext + signature)

        except ConnectionError:
            self.close_client(f'{bcolors.WARNING}Error: Could not send data!!!{bcolors.ENDC}')

    def challenge_response(self):
        '''
        Do challenge response protocol
        
        Generate and send a nonce. Receive f(nonce) from server and validate it. f(x) = x ** 2
        '''
        # Generate nonce
        nonce = randint(0, 65535)

        # Try to send nonce to server
        try: M.send(self.server_socket, self.session_key, self.private_key, 'I', nonce)
        except socket.error:
            self.close_client(f'{bcolors.FAIL}Error: Could not send nonce to server{bcolors.ENDC}')

        # Try and get nonce ** 2 from server
        try: f_nonce = M.get(self.server_socket, self.session_key, self.server_key, 'I', 4)[0]
        except socket.error:
            self.close_client(f'{bcolors.FAIL}Error: Could not get f(nonce) from server{bcolors.ENDC}')

        # Ensure matching values
        if nonce ** 2 != f_nonce:
            self.close_client(f'{bcolors.FAIL}Error: f(nonce) does not match{bcolors.ENDC}')

    def get_cards_and_result(self) -> tuple[3]:
        '''
        Get and validate cards and result from server

        This function will call close_client() if there are 
        discrepancies in the player card or the result
        
        Returns -
            tuple: a 3-tuple with player_card, opponent_card, and result
        '''

        # Attempt to get cards and result from server
        try: player_card, opponent_card, result = M.get(self.server_socket, self.session_key, self.server_key, 'I I I', 12)
        except socket.error:
            self.close_client(f'{bcolors.FAIL}Error: could not get cards{bcolors.ENDC}')
        except ValueError:
            self.close_client(f'{bcolors.FAIL}Error: could not verify digital signature{bcolors.ENDC}')

        # Validate player card
        if player_card != self.card:
            self.close_client(f'{bcolors.FAIL}Error: Card does not match{bcolors.ENDC}')

        # Determine result based on supplied cards
        if player_card == opponent_card:
            my_result = 0
        elif player_card > opponent_card:
            my_result = self.player_num
        else:
            my_result = 2 if self.player_num == 1 else 1

        # Verify result
        if my_result != result:
            self.close_client(f'{bcolors.FAIL}Error: Discrepancy in results{bcolors.ENDC}')

        # Return cards and result
        return player_card, opponent_card, result

    def close_client(self, message: str) -> None:
        '''
        Close the client and exit program
        
        Parameters -
            message(str): the message to print before program exit
        '''

        # print closing message
        print(f'{message}\n\nClosing client . . .\n\n\n\n')

        # close socket and exit
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

    # Start Game #################################################################################
    player.start_game()

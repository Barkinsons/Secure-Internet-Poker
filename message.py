##########################################################################
# message.py - Send and get functions according to a specific format     #
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

import struct

from mydigitalsignature import DigitalSignature as DS
from Cryptodome.Hash import SHA1
from Cryptodome.Cipher import AES

# Used for type hinting
import socket
from Cryptodome.PublicKey import RSA, DSA

class Message:
    
    def get(connection: socket.socket, session_key: bytes, public_key: RSA.RsaKey | DSA.DsaKey, format: str, p_size: int) -> tuple:
        '''
        Get and return objects from connection according to format

        This function receives a message over the connection and
        decrypts it according to the AES GCM mode format, with an
        included digital signatue

        After verifying the ciphertext and digital signature it
        returns the object according to the format

        Parameters -
            connection (socket.socket): the connection to receive the message over
            session_key (bytes): the AES key for decryption
            public_key (RSA.RsaKey | DSA.DsaKey): the public key for verification of the digital signature
            format (str): the format for use in struct.unpack()
            p_size (int): the total size of expected object in bytes

        Returns -
            tuple: a tuple of objects
        '''
        # Get size of message to receive
        size_bytes = connection.recv(4)
        size = struct.unpack('I', size_bytes)[0]

        # Receive message over connection
        message = connection.recv(size)

        # Parse message
        nonce, tag, ciphertext, signature = message[:16], message[16:32], message[32:32+p_size], message[32+p_size:]

        # Create AES object for decryption
        cipher = AES.new(session_key, AES.MODE_GCM, nonce)

        # Decrypt and verify ciphertext
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # Verify digital signature
        DS.verify_digital_signature(SHA1.new(plaintext), signature, public_key)
        
        # Return tuple of objects
        return struct.unpack(format, plaintext)


    def send(connection: socket.socket, session_key: bytes, private_key: RSA.RsaKey | DSA.DsaKey, format: str, *args):
        '''
        Send objects over connection according to format

        This function sends a message over the connection. The plaintext
        is created using *args and the format and is encrypted using the 
        session key in AES.MODE_GCM. The final message sent includes the 
        length of the message, the ciphertext, and the digital signature

        Parameters - 
            connection (socket.socket): the connection for sending the message
            session_key (bytes): the AES key used for encryption
            private_key (RSA.RsaKey | DSA.DsaKey): The private key used for signing the message
            format (str): the format for use in struct.pack()
            *args: the object to be sent over the connection
        '''
        # Create plaintext
        plaintext = struct.pack(format, *args)

        # Create digital signature
        signature = DS.generate_digital_signature(SHA1.new(plaintext), private_key)

        # Create AES cipher object for encryption
        cipher = AES.new(session_key, AES.MODE_GCM)

        # Encrypt and digest plaintext
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Create message
        message = cipher.nonce + tag + ciphertext + signature

        # Send message with message length prepended
        connection.send(struct.pack(f'I', len(message)) + message)
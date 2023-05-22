##########################################################################
# mydigitalsignature.py - Dynamic generation and verification of ds's    #
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

from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Hash import SHA256

class DigitalSignature:
    '''
    A class to hold digital signature generation and verification functions
    
    Methods -
        generate_digital_signature(msg_hash, key):
            Generates the digital signature for some hash given asymmetric key

        verify_digital_signature(msg_hash, signature, key)
            Verifies the digital signature given hash and asymmetric key
    '''

    def generate_digital_signature(msg_hash: SHA256.SHA256Hash, key: RSA.RsaKey | DSA.DsaKey) -> bytes:
        '''
        Generates the digital signature for some hash given asymmetric key

        This function takes a SHA256Hash and an asymmetric key and generates 
        a digital signature according to the key type
        
        Parameters -
            msg_hash: the SHA256Hash object
            key: the asymmetric key used to generate the digital signature

        Returns - 
            bytes: the digital signature

        Errors -
            TypeError: key type not supported
        '''

        # Given RSAkey
        if type(key) == RSA.RsaKey:
            return pkcs1_15.new(key).sign(msg_hash)
        
        # Given DSAkey
        elif type(key) == DSA.DsaKey:
            return DSS.new(key, 'fips-186-3').sign(msg_hash)
        
        # Unknown key type
        else:
            raise TypeError(f'key type not supported: ({type(key)})')

    def verify_digital_signature(msg_hash: SHA256.SHA256Hash, signature: bytes, key: RSA.RsaKey | DSA.DsaKey):
        '''
        Verifies the digital signature given hash and asymmetric key

        This function attempts to verify a digital signature using the SHA256Hash
        and an asymmetric key according to the key type

        Parameters -
            plaintext (bytes): the plaintext used to generate the hash
            key (RsaKey): the rsakey used to verify the digital signature

        Errors - 
            TypeError: key type not supported
            ValueError: could not verify the digital signature
        '''

        # Given RSAkey
        if type(key) == RSA.RsaKey:
            pkcs1_15.new(key).verify(msg_hash, signature)

        # Given DSAkey
        elif type(key) == DSA.DsaKey:
            DSS.new(key, 'fips-186-3').verify(msg_hash, signature)

        # Unknown key type
        else:
            raise TypeError(f'key type not supported: ({type(key)})')
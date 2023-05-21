from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Hash import SHA1

class DigitalSignature:

    def generate_digital_signature(msg_hash: SHA1.SHA1Hash, key: RSA.RsaKey | DSA.DsaKey):
        '''
        Generates the digital signature for some hash given asymmetric key

        This function takes a SHA1Hash and an asymmetric key and generates 
        a digital signature according to the key type
        
        Parameters -
            msg_hash: the SHA1Hash object
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


        
    def verify_digital_signature(msg_hash: SHA1.SHA1Hash, signature: bytes, key: RSA.RsaKey | DSA.DsaKey):
        '''
        Verifies the digital signature given hash and asymmetric key

        This function attempts to verify a digital signature using the SHA1Hash
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
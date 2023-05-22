import struct
from mydigitalsignature import DigitalSignature as DS
from Cryptodome.Hash import SHA1
from Cryptodome.Cipher import AES

class Message:
    
    def get(connection, session_key, public_key, format, p_size):

        size_bytes = connection.recv(4)
        size = struct.unpack('I', size_bytes)[0]

        message = connection.recv(size)

        nonce, tag, ciphertext, signature = message[:16], message[16:32], message[32:32+p_size], message[32+p_size:]

        cipher = AES.new(session_key, AES.MODE_GCM, nonce)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        DS.verify_digital_signature(SHA1.new(plaintext), signature, public_key)
        
        return struct.unpack(format, plaintext)


    def send(connection, session_key, private_key, format, *args):
        plaintext = struct.pack(format, *args)

        signature = DS.generate_digital_signature(SHA1.new(plaintext), private_key)

        cipher = AES.new(session_key, AES.MODE_GCM)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        message = cipher.nonce + tag + ciphertext + signature

        connection.send(struct.pack(f'I', len(message)) + message)

import base64
import binascii
import os
import struct
import time
import math


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class InvalidToken(Exception):
    def __init__(self):
        super(InvalidToken, self).__init__("Invalid Token. Wrong version, \
                    exceeded time to live \or CMAC signature is incorrect.")

class Fernet(object):
    def __init__(self, key, backend=None):
        if backend is None:
            backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet key must be 32 url-safe base64-encoded bytes."
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]
        self._backend = backend

    @classmethod
    def generate_key(self):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        '''
        Fernet 0x91 Authenticated Encyption
        Input: message
        Output: encrypted + authenticated message
        '''

        VERSION = b'\x91'
        TIMESTAMP = struct.pack('>Q', time.time())
        IV = os.urandom(16)
        ciphertext = self._AES_CTR_encrypt(data, IV, self._encryption_key)
        cmac_input = VERSION + TIMESTAMP + IV + ciphertext
        cmac_length = len(cmac_input)
        CMAC = self._AES_CMAC_generate(self._signing_key, cmac_input, cmac_length)

        token = base64.urlsafe_b64encode(cmac_input + CMAC)

        return token

    def decrypt(self, token, timetolive=None):
        '''
        Fernet 0x91 Authenticated Decryption
        Input: ciphertext
        Output: plaintext if valid signature, else exception is thrown
        '''

        ciphertext = base64.urlsafe_b64decode(token)

        # breakdown the token into the corresponding parts as per definition
        version = ciphertext[0]             # first 8 bits (1 byte)
        timestamp = ciphertext[1:9]         # next 64 bits (8 bytes)
        IV = ciphertext[9:25]               # next 128 bits (16 bytes)
        cipher_field = ciphertext[25:-16]   # next bits until last 128 bits
        orig_CMAC = ciphertext[-16:]        # last 128 bits(16 bytes)

        if version != b'\x91':
            raise InvalidToken()

        # if user provided timetolive is exceeded throw exception
        if timetolive:
            timestamp = self._bytes_to_integer(timestamp)
            timenow = int(time.time())
            age = timenow - timestamp
            if age < 0 or age > timetolive:
                raise InvalidToken()

        cmac_input = ciphertext[:-16]
        cmac_length = len(cmac_input)
        re_CMAC = self._AES_CMAC_generate(self._signing_key, cmac_input, cmac_length)

        # if signature is invalid, throw exception
        if re_CMAC != orig_CMAC:
            raise InvalidToken()

        data = self._AES_CTR_decrypt(cipher_field, IV, self._encryption_key)

        return data

    def _AES_ECB(self, plaintext, key):
        '''
        AES 128 block cipher (ECB mode)
        Input: plaintext, key
        Output: ciphertext
        '''
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self._backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    def _AES_CTR_encrypt(self, plaintext, iv, key):
        '''
        AES_CTR encryption
        Input: plaintext, iv, key
        Output: ciphertext
        '''
        msgs = self._split_into_blocks(plaintext, 16)

        ctrblk = self._bytes_to_integer(iv)
        ciphertext = []
        for block in msgs:
            L = len(block)
            E = self._AES_ECB(self._integer_to_bytes(ctrblk), key)
            ciphertext.append(self._xor(block, E[:L]))
            ctrblk = self._increment_integer(ctrblk)
        return ''.join(ciphertext)

    def _AES_CTR_decrypt(self, ciphertext, iv, key):
        '''
        AES_CTR decryption
        Input: ciphertext, iv, key
        Output: plaintext
        '''
        cts = self._split_into_blocks(ciphertext, 16)

        ctrblk = self._bytes_to_integer(iv)
        plaintext = []
        for block in cts:
            L = len(block)
            E = self._AES_ECB(self._integer_to_bytes(ctrblk), key)
            plaintext.append(self._xor(block, E[:L]))
            ctrblk = self._increment_integer(ctrblk)
        return ''.join(plaintext)

    def _generate_subkey(self, key):
        '''
        AES_CMAC subkey generation
        Input: key (128bit)
        Output: k1 (128bit), k2 (128bit)
        '''

        # assert incorrent length of key
        assert len(key) == 16

        CONST_ZERO = 0x00000000000000000000000000000000
        CONST_RB = 0x00000000000000000000000000000087

        L = self._AES_ECB(self._integer_to_bytes(CONST_ZERO), key)
        L = self._bytes_to_integer(L)

        if self._msb(L) == 0:
            K1 = L << 1
            K1 = self._get_128_bits(K1)
            K1 = self._integer_to_bytes(K1)
        else:
            _L = (L << 1)
            _L = self._get_128_bits(_L)
            K1 = self._xor(self._integer_to_bytes(_L), self._integer_to_bytes(CONST_RB))

        K1 = self._bytes_to_integer(K1)

        if self._msb(K1) == 0:
            K2 = K1 << 1
            K2 = self._get_128_bits(K2)
            K2 = self._integer_to_bytes(K2)
        else:
            _K1 = (K1 << 1)
            _K1 = self._get_128_bits(_K1)
            K2 = self._xor(self._integer_to_bytes(_K1), self._integer_to_bytes(CONST_RB))

        K1 = self._integer_to_bytes(K1)
        return K1, K2

    def _AES_CMAC_generate(self, K, M, length):
        '''
        AES_CMAC signature generation
        Input: Key, message, message length
        Output: signature of message
        '''
        CONST_ZERO = 0x00000000000000000000000000000000
        CONST_BSIZE = 16

        msgs = self._split_into_blocks(M, 16)
        msgs = list(msgs)

        K1, K2 = self._generate_subkey(K)

        n = int(math.ceil(length/float(CONST_BSIZE)))

        if n == 0:
            n = 1
            flag = False
        else:
            flag = True if length % CONST_BSIZE == 0 else False

        if flag:
            msgs[-1] = self._xor(msgs[-1], K1)
        else:
            if not msgs:
                msgs.append(self._xor(self._padding(msgs), K2))
            else:
                msgs[-1] = self._xor(self._padding(msgs[-1]), K2)


        X = self._integer_to_bytes(CONST_ZERO)
        for i in range(0, n-1):
            Y = self._xor(X, msgs[i])
            X = self._AES_ECB(Y, K)
        Y = self._xor(msgs[-1], X)
        T = self._AES_ECB(Y, K)
        return T

    def _AES_CMAC_verify(self, K, M, length, T1):
        '''
        AES_CMAC signature verification
        Input: key, messsage, message length, signature
        Output: message valid or invalid (bool)
        '''
        T2 = self._AES_CMAC_generate(K, M, length)
        return True if T2 == T1 else False

    def _bytes_to_integer(self, bytearr):
        '''
        bytes to integer conversion
        Input: bytestream (length 16)
        Output: integer (128 bits)
        '''
        assert len(bytearr) > 0
        to_hex = bytearr.encode('hex')
        to_int = int(to_hex, 16)
        return to_int

    def _integer_to_bytes(self, integer):
        '''
        integer to bytes conversion
        Input: integer (128 bits)
        Output: bytestream (length 16)
        '''
        assert integer < 2**128-1
        to_hex = "{0:032x}".format(integer)
        to_bytes = to_hex.decode('hex')
        return to_bytes

    def _increment_integer(self, x):
        '''
        increments a 128 bit integer with overflow
        Input: integer (128 bits)
        Output: integer (128 bits)
        '''
        assert x < 2**128
        assert x >= 0
        return (x + 1) % (2**128)

    def _padding(self, x):
        '''
        byte aligned padding, 10^i
        Input: bytestream
        Output: padded bytestream
        '''
        if len(x) < 16:
            x += chr(128)
        while len(x) < 16:
            x += chr(0)
        return x

    def _msb(self, x):
        '''
        Most significant bit
        Input: integer
        Output: most signifanct bit
        '''
        mask = 1 << 127
        return x & mask

    def _get_128_bits(self, x):
        '''
        mask which keeps only first 128 bits
        Input: integer (any length)
        Output: integer (128 bits)
        '''
        mask = (1 << 128) - 1
        return x & mask

    def _xor(self, a, b):
        """
        xors two raw byte streams.
        """
        assert len(a) == len(b), "Lengths of two strings are not same. a = {}, b = {}".format(len(a), len(b))
        return ''.join(chr(ord(ai)^ord(bi)) for ai,bi in zip(a,b))

    def _split_into_blocks(self, msg, l):
        '''
        splits a message into bytes of provided length
        Input: message
        Output: generator of message blocks
        '''
        while msg:
            yield msg[:l]
            msg = msg[l:]

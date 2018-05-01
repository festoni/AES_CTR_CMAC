
import base64
import binascii
import os
import struct
import time
import math


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class InvalidToken(Exception):
    pass

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
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        #TODO

        version = b'\x91'
        t = time.time()
        timestamp = struct.pack('>Q', t)
        IV = os.urandom(16)

        return data

    def decrypt(self, token, timetolive=None):
        #TODO
        return token

    def _AES_CTR_encrypt(self, plaintext, iv, key):
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
        cts = self._split_into_blocks(ciphertext, 16)

        ctrblk = self._bytes_to_integer(iv)
        plaintext = []
        for block in cts:
            L = len(block)
            E = self._AES_ECB(self._integer_to_bytes(ctrblk), key)
            plaintext.append(self._xor(block, E[:L]))
            ctrblk = self._increment_integer(ctrblk)
        return ''.join(plaintext)

    def _AES_ECB(self, plaintext, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self._backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    def _AES_CMAC_encrypt(self):
        pass

    def _bytes_to_integer(self, bytearr):
        to_hex = bytearr.encode('hex')
        to_int = int(to_hex, 16)
        return to_int


    def _increment_integer(self, x):
        return (x + 1) % (2**128)

    def _generate_subkey(self, key):
        CONST_ZERO = 0x00000000000000000000000000000000
        CONST_RB = 0x00000000000000000000000000000087

        # step 1
        L = self._AES_ECB(self._integer_to_bytes(CONST_ZERO), key)
        L = self._bytes_to_integer(L)

        # step 2
        if self._msb(L) == 0:
            K1 = L << 1
            K1 = self._get_128_bits(K1)
            K1 = self._integer_to_bytes(K1)
        else:
            _L = (L << 1)
            _L = self._get_128_bits(_L)
            K1 = self._xor(self._integer_to_bytes(_L), self._integer_to_bytes(CONST_RB))

        K1 = self._bytes_to_integer(K1)

        # step 3
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

    def _AES_CMAC_encrypt(self, K, M, length):
        CONST_ZERO = 0x00000000000000000000000000000000
        CONST_BSIZE = 16

        msgs = self._split_into_blocks(M, 16)
        msgs = list(msgs)

        # STEP 1
        K1, K2 = self._generate_subkey(K)

        # STEP 2
        n = math.ceil(length/float(CONST_BSIZE))

        # STEP 3
        if n == 0:
            n = 1
            flag = False
        else:
            flag = True if length % CONST_BSIZE == 0 else False

        # STEP 4
        if flag:
            msgs[-1] = self._xor(msgs[-1], K1)
        else:
            msgs[-1] = self._xor(self._padding(msgs[-1]), K2)

        # STEP 5
        X = self._integer_to_bytes(CONST_ZERO)
        for i in range(0, n-1):
            Y = self._xor(X, msgs[i])
            X = self._AES_ECB(Y, K)
        Y = self._xor(msgs[-1], X)
        T = self._AES_ECB(Y, K)
        return T

    def _padding(self, x):
        if len(x) < 16:
            x += chr(128)
        while len(x) < 16:
            x += chr(0)
        return x

    def _msb(self, x):
        mask = 1 << 127
        return x & mask

    def _get_128_bits(self, x):
        mask = (1 << 128) - 1
        return x & mask

    def _xor(self, a, b):
        """
        xors two raw byte streams.
        """
        assert len(a) == len(b), "Lengths of two strings are not same. a = {}, b = {}".format(len(a), len(b))
        return ''.join(chr(ord(ai)^ord(bi)) for ai,bi in zip(a,b))

    def _split_into_blocks(self, msg, l):
        while msg:
            yield msg[:l]
            msg = msg[l:]
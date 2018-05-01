from fernet import Fernet
import pytest
import base64
import os

class TestFernet:
    def test_Functionality(self):
        pass
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # decrypt(encrypt(msg)) == msg
        for i in xrange(20):
            msg = os.urandom(6)
            assert fernet.decrypt(fernet.encrypt(msg)) == msg

    def test_bytes(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        for i in range(100000):
            b = os.urandom(16)
            assert fernet._integer_to_bytes(fernet._bytes_to_integer(b)) == b

    def test_CTR(self):
        KEY = 'AE6852F8121067CC4BF7A5765577F39E'.decode('hex')
        IV = '00000030000000000000000000000001'.decode('hex')
        PLAINTEXT = '53696E676C6520626C6F636B206D7367'.decode('hex')
        CIPHERTEXT = 'E4095D4FB7A7B3792D6175A3261311B8'.decode('hex')

        key = Fernet.generate_key()
        fernet = Fernet(key)
        # print(fernet._AES_CTR_encrypt(PLAINTEXT, IV, KEY))
        # print(CIPHERTEXT)
        # assert fernet._AES_CTR_encrypt(PLAINTEXT, IV, KEY) == CIPHERTEXT

if __name__ == "__main__":
    a = TestFernet()
    a.test_Functionality()

from fernet import Fernet
import pytest
import base64
import os

class TestFernet:

    def test_Functionality(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # decrypt(encrypt(msg)) == msg
        for i in xrange(20):
            msg = os.urandom(6)
            assert fernet.decrypt(fernet.encrypt(msg)) == msg

    def test_Functionality_extensive(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # decrypt(encrypt(msg)) == msg
        for i in xrange(100):
            for l in range(20):
                msg = os.urandom(l)
                assert fernet.decrypt(fernet.encrypt(msg)) == msg

    def test_xor(self):
        # check xor functionality
        key = Fernet.generate_key()
        fernet = Fernet(key)

        x = bytes(bytearray(16))
        for i in xrange(20):
            y = os.urandom(16)
            assert(fernet._xor(x, y) == y) # xor of 0 and y == y

    def test_xor_bad_length(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # check xor functionality
        x = bytes(bytearray(16))
        for i in xrange(1, 20):
            if i == 16:
                continue
            y = os.urandom(i)
            with pytest.raises(AssertionError) as e:
                fernet._xor(x, y)

    def test_integer_bytes_conversion(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        for i in range(10000):
            b = os.urandom(16)
            assert fernet._integer_to_bytes(fernet._bytes_to_integer(b)) == b

    def test_integer_bytes_conversion2(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        for i in range(10000):
            assert fernet._bytes_to_integer(fernet._integer_to_bytes(i)) == i

    def test_big_integer(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)
        with pytest.raises(AssertionError) as e:
            fernet._integer_to_bytes(2**128)

    def test_empty_bytes(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        b = os.urandom(0)
        with pytest.raises(AssertionError) as e:
            fernet._bytes_to_integer(b)

    def test_increment_integer(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # test normal behavior
        for i in range(100):
            assert fernet._increment_integer(i) == i + 1

        # test edge case
        i = 2**128-1
        assert fernet._increment_integer(i) == 0

        # test big integer
        with pytest.raises(AssertionError) as e:
            fernet._increment_integer(2**128)

        # test negative integer
        with pytest.raises(AssertionError) as e:
            fernet._increment_integer(-1)

    def test_CTR_test_vectors(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        KEY = 'AE6852F8121067CC4BF7A5765577F39E'.decode('hex')
        IV = '00000030000000000000000000000001'.decode('hex')
        PLAINTEXT = '53696E676C6520626C6F636B206D7367'.decode('hex')
        CIPHERTEXT = 'E4095D4FB7A7B3792D6175A3261311B8'.decode('hex')

        assert fernet._AES_CTR_encrypt(PLAINTEXT, IV, KEY) == CIPHERTEXT
        assert fernet._AES_CTR_decrypt(CIPHERTEXT, IV, KEY) == PLAINTEXT

        KEY = '7E24067817FAE0D743D6CE1F32539163'.decode('hex')
        IV = '006CB6DBC0543B59DA48D90B00000001'.decode('hex')
        PLAINTEXT = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'.decode('hex')
        CIPHERTEXT = '5104A106168A72D9790D41EE8EDAD388EB2E1EFC46DA57C8FCE630DF9141BE28'.decode('hex')

        assert fernet._AES_CTR_encrypt(PLAINTEXT, IV, KEY) == CIPHERTEXT
        assert fernet._AES_CTR_decrypt(CIPHERTEXT, IV, KEY) == PLAINTEXT

        KEY = '7691BE035E5020A8AC6E618529F9A0DC'.decode('hex')
        IV = '00E0017B27777F3F4A1786F000000001'.decode('hex')
        PLAINTEXT = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223'.decode('hex')
        CIPHERTEXT = 'C1CF48A89F2FFDD9CF4652E9EFDB72D74540A42BDE6D7836D59A5CEAAEF3105325B2072F'.decode('hex')

        assert fernet._AES_CTR_encrypt(PLAINTEXT, IV, KEY) == CIPHERTEXT
        assert fernet._AES_CTR_decrypt(CIPHERTEXT, IV, KEY) == PLAINTEXT

    def test_CTR_encrypt(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

    def test_CTR_functionality(self):
        key = Fernet.generate_key()
        fernet = Fernet(key)

        for i in range(20):
            data = os.urandom(i)
            key = os.urandom(16)
            iv = os.urandom(16)

            assert fernet._AES_CTR_decrypt(fernet._AES_CTR_encrypt(data, iv, key), iv, key) == data



if __name__ == "__main__":
    a = TestFernet()
    a.test_Functionality()

from fernet import Fernet, InvalidToken
import pytest
import base64
import os
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac

class TestFernet:

    def test_Functionality(self):
        # basic fernet 0x91 functionality test 
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # decrypt(encrypt(msg)) == msg
        for i in xrange(20):
            msg = os.urandom(6)
            assert fernet.decrypt(fernet.encrypt(msg)) == msg

    def test_xor(self):
        # check xor for normal functionality
        key = Fernet.generate_key()
        fernet = Fernet(key)

        x = bytes(bytearray(16))
        for i in xrange(20):
            y = os.urandom(16)
            assert(fernet._xor(x, y) == y) # xor of 0 and y == y

    def test_xor_bad_length(self):
        # test xor function when given mismatching lengths
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
        # test bytes to integer, then integer to bytes == original
        key = Fernet.generate_key()
        fernet = Fernet(key)

        for i in range(10000):
            b = os.urandom(16)
            assert fernet._integer_to_bytes(fernet._bytes_to_integer(b)) == b

    def test_integer_bytes_conversion2(self):
        # test integer to bytes, then bytes to integer == original
        key = Fernet.generate_key()
        fernet = Fernet(key)

        for i in range(10000):
            assert fernet._bytes_to_integer(fernet._integer_to_bytes(i)) == i

    def test_big_integer(self):
        # test _integer_to_bytes when given too big an integer
        key = Fernet.generate_key()
        fernet = Fernet(key)
        with pytest.raises(AssertionError) as e:
            fernet._integer_to_bytes(2**128)

    def test_empty_bytes(self):
        # test _bytes_to_integer function when given empty bytes
        key = Fernet.generate_key()
        fernet = Fernet(key)

        b = os.urandom(0)
        with pytest.raises(AssertionError) as e:
            fernet._bytes_to_integer(b)

    def test_increment_integer(self):
        # test the increment integer function
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

    def test_AES_ECB(self):
        # AES_ECB_128 test with RFC test vectors
        key = Fernet.generate_key()
        fernet = Fernet(key)

        KEY = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
        AES_128 = '7df76b0c1ab899b33e42f047b91b546f'.decode('hex')
        CONST_ZERO = 0x00000000000000000000000000000000

        assert fernet._AES_ECB(fernet._integer_to_bytes(CONST_ZERO), KEY) == AES_128

    def test_CTR_test_vectors(self):
        # test CTR encryption and decryption using official RFC test vectors
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
        # test CTR encrypt function (encrypt with our API, decrypt with library)
        key = Fernet.generate_key()
        fernet = Fernet(key)

        for i in range(20):
            data = os.urandom(i)
            key = os.urandom(16)
            iv = os.urandom(16)

            # encrypt with our API
            ct = fernet._AES_CTR_encrypt(data, iv, key)

            # decrypt with library API
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            pt = decryptor.update(ct) + decryptor.finalize()
            assert data == pt

    def test_CTR_decrypt(self):
        # test CTR decrypt function (encrypt with library API, decrypt with ours)
        key = Fernet.generate_key()
        fernet = Fernet(key)

        for i in range(20):
            data = os.urandom(i)
            key = os.urandom(16)
            iv = os.urandom(16)

            # encrypt with library APIs
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(data) + encryptor.finalize()

            # decrypt with our APIs
            pt = fernet._AES_CTR_decrypt(ct, iv, key)
            assert data == pt

    def test_CTR_functionality(self):
        # test CTR functionality (decrypt(encrypt(msg)) == msg)
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # test encrypt than decrypt gives back original message
        for i in range(20):
            data = os.urandom(i)
            key = os.urandom(16)
            iv = os.urandom(16)

            assert fernet._AES_CTR_decrypt(fernet._AES_CTR_encrypt(data, iv, key), iv, key) == data

    def test_subkey_generation(self):
        # test subkey generation using RFC test vectors
        key = Fernet.generate_key()
        fernet = Fernet(key)

        KEY = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
        AES_128 = '7df76b0c1ab899b33e42f047b91b546f'.decode('hex')
        K1 = 'fbeed618357133667c85e08f7236a8de'.decode('hex')
        K2 = 'f7ddac306ae266ccf90bc11ee46d513b'.decode('hex')

        K1_, K2_ = fernet._generate_subkey(KEY)
        assert K1 == K1_ and K2 == K2_

    def test_subkey_gen_bad_length(self):
        # test subkey generation function when given bad input length
        key = Fernet.generate_key()
        fernet = Fernet(key)

        KEY = os.urandom(15)
        with pytest.raises(AssertionError) as e:
            fernet._generate_subkey(KEY)

    def test_CMAC_test_vectors(self):
        # test using official RFC AES_CMAC test vectors
        key = Fernet.generate_key()
        fernet = Fernet(key)

        K = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')

        LENGTH = 0
        M = ''
        CMAC = 'bb1d6929e95937287fa37d129b756746'.decode('hex')
        assert fernet._AES_CMAC_generate(K, M, LENGTH) == CMAC

        LENGTH = 16
        M = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
        CMAC = '070a16b46b4d4144f79bdd9dd04a287c'.decode('hex')
        assert fernet._AES_CMAC_generate(K, M, LENGTH) == CMAC

        LENGTH = 40
        M = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'.decode('hex')
        CMAC = 'dfa66747de9ae63030ca32611497c827'.decode('hex')
        assert fernet._AES_CMAC_generate(K, M, LENGTH) == CMAC

        LENGTH = 64
        M = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'.decode('hex')
        CMAC = '51f0bebf7e3b9d92fc49741779363cfe'.decode('hex')
        assert fernet._AES_CMAC_generate(K, M, LENGTH) == CMAC

    def test_CMAC_generate(self):
        # test AES_CMAC generation
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # test against the cryptographi.io library APIs
        for i in range(20):
            M = os.urandom(i)
            K = os.urandom(16)

            # use library's API to generate CMAC
            c = cmac.CMAC(algorithms.AES(K), backend=default_backend())
            c.update(M)
            lib_cmac = c.finalize()

            # use our function to generate CMAC
            cmac_ = fernet._AES_CMAC_generate(K, M, len(M))

            # verify library CMAC vs our CMAC
            assert cmac_ == lib_cmac

    def test_CMAC_verify(self):
        # test CMAC verification function
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # test against the cryptography.io library APIs
        for i in range(20):
            M = os.urandom(i)
            K = os.urandom(16)

            # use library API generation
            c = cmac.CMAC(algorithms.AES(K), backend=default_backend())
            c.update(M)
            lib_cmac = c.finalize()

            # verify a library generated cmac
            assert fernet._AES_CMAC_verify(K, M, len(M), lib_cmac)

            # verify against our own API
            cmac_ = fernet._AES_CMAC_generate(K, M, len(M))
            assert fernet._AES_CMAC_verify(K, M, len(M), cmac_)

            # # library verify our generated cmac
            c = cmac.CMAC(algorithms.AES(K), backend=default_backend())
            c.update(M)
            try:
                c.verify(cmac_)
            except Exception:
                raise Exception

    def test_Functionality_extensive(self):
        # extensively test the decrpytion(encryption(msg)) == msg
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # decrypt(encrypt(msg)) == msg
        for i in xrange(100):
            for l in range(20):
                msg = os.urandom(l)
                assert fernet.decrypt(fernet.encrypt(msg)) == msg

    def test_bad_version(self):
        # test incorrect version of Fernet 0x91
        key = Fernet.generate_key()
        fernet = Fernet(key)

        ct = fernet.encrypt('Secret message!')
        ct = list(base64.urlsafe_b64decode(ct))     # decode ciphertext
        ct[0] = b'\x00'                             # change version
        ct = ''.join(ct)
        ct = base64.urlsafe_b64encode(ct)           # encode ciphertext

        with pytest.raises(InvalidToken) as e:
            fernet.decrypt(ct)

    def test_timeout(self):
        # test exceeded time to live
        key = Fernet.generate_key()
        fernet = Fernet(key)

        ct = fernet.encrypt('Another secret message!')
        time.sleep(3)
        with pytest.raises(InvalidToken) as e:
            fernet.decrypt(ct, 2)

    def test_bad_CMAC(self):
        # test bad CMAC signature
        key = Fernet.generate_key()
        fernet = Fernet(key)

        ct = fernet.encrypt('Aanother message!')
        ct = list(base64.urlsafe_b64decode(ct))     # decode ciphertext
        ct.append(b'\x00')                          # modify CMAC
        ct = ''.join(ct)
        ct = base64.urlsafe_b64encode(ct)           # encode ciphertext

        with pytest.raises(InvalidToken) as e:
            fernet.decrypt(ct)

if __name__ == "__main__":
    a = TestFernet()
    a.test_Functionality()

from fernet import Fernet
import pytest
import base64
import os


key = Fernet.generate_key()
fernet = Fernet(key)


# data = "Hello my very good friend"
# ct = fernet.encrypt(data)
# print(ct)
#
# pt = fernet.decrypt(ct)
# print(pt)

c = 0
for i in range(100):
    for l in range(10):
        data = os.urandom(l)
        if fernet.decrypt(fernet.encrypt(data)) != data:
            c += 1

print 'SUCCESS:', 100*10 - c
print 'FAIL:   ', c

# length = 64
# M1 = ''
# # M2 = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
# M3 = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'.decode('hex')
# M4 = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'.decode('hex')
# K = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
# T = fernet._AES_CMAC_generate(K, M4, length)
# print(T.encode('hex'))



# KEY = 'AE6852F8121067CC4BF7A5765577F39E'.decode('hex')
# IV = '00000030000000000000000000000001'.decode('hex')
# PLAINTEXT = '53696E676C6520626C6F636B206D7367'.decode('hex')
# CIPHERTEXT = 'E4095D4FB7A7B3792D6175A3261311B8'.decode('hex')
#
# print(fernet._AES_CTR_encrypt(PLAINTEXT, IV, KEY) == CIPHERTEXT)
# print(fernet._AES_CTR_decrypt(CIPHERTEXT, IV, KEY) == PLAINTEXT)
#
# KEY = '7E24067817FAE0D743D6CE1F32539163'.decode('hex')
# IV = '006CB6DBC0543B59DA48D90B00000001'.decode('hex')
# PLAINTEXT = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'.decode('hex')
# CIPHERTEXT = '5104A106168A72D9790D41EE8EDAD388EB2E1EFC46DA57C8FCE630DF9141BE28'.decode('hex')
#
# print(fernet._AES_CTR_encrypt(PLAINTEXT, IV, KEY) == CIPHERTEXT)
# print(fernet._AES_CTR_decrypt(CIPHERTEXT, IV, KEY) == PLAINTEXT)
#
# KEY = '7691BE035E5020A8AC6E618529F9A0DC'.decode('hex')
# IV = '00E0017B27777F3F4A1786F000000001'.decode('hex')
# PLAINTEXT = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223'.decode('hex')
# CIPHERTEXT = 'C1CF48A89F2FFDD9CF4652E9EFDB72D74540A42BDE6D7836D59A5CEAAEF3105325B2072F'.decode('hex')
#
# print(fernet._AES_CTR_encrypt(PLAINTEXT, IV, KEY) == CIPHERTEXT)
# print(fernet._AES_CTR_decrypt(CIPHERTEXT, IV, KEY) == PLAINTEXT)
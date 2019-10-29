from Crypto.Cipher import AES, PKCS1_OAEP
import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA


class AESUtil():
    def __init__(self, key):
        self.key = key

    def encryptByCTR(self, data):
        if type(self.key) is str:
            cipher = AES.new(bytes(self.key, 'utf8'), AES.MODE_CTR)
        elif type(self.key) is bytes:
            cipher = AES.new(self.key, AES.MODE_CTR)
        result = cipher.encrypt(bytes(data, 'utf8'))
        nonce = cipher.nonce
        return {"data": base64.b64encode(result).decode(), "nonce": base64.b64encode(nonce).decode()}

    def decryptByCTR(self, data: str, nonce: str):
        if type(self.key) is str:
            cipher = AES.new(bytes(self.key, 'utf8'), AES.MODE_CTR,
                            nonce=base64.b64decode(nonce))
        if type(self.key) is bytes:
            cipher = AES.new(self.key, AES.MODE_CTR,
                            nonce=base64.b64decode(nonce))
        return cipher.encrypt(base64.b64decode(data)).decode()

    def encryptByECB(self, data: str):
        cipher = AES.new(bytes(self.key, 'utf8'), AES.MODE_ECB)
        result = cipher.encrypt(pad(bytes(data, 'utf8'), AES.block_size))
        return base64.b64encode(result).decode()

    def decryptByECB(self, data: str):
        cipher = AES.new(bytes(self.key, 'utf8'), AES.MODE_ECB)
        return unpad(cipher.decrypt(base64.b64decode(data)), AES.block_size)


class RSAUtil():
    def createKey(self, key_length=1024):
        key = RSA.generate(key_length)
        return {"private_key": key.export_key().decode(), "public_key": key.publickey().export_key().decode()}

    def encrypt(self, publick_key: str, data):
        key = RSA.import_key(publick_key)
        cipher = PKCS1_OAEP.new(key)
        if type(data) is str:
            return base64.b64encode(cipher.encrypt(bytes(data, 'utf8'))).decode()
        elif type(data) is bytes:
            return base64.b64encode(cipher.encrypt(data)).decode()

    def decrypt(self, private_key: str, data: str):
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(base64.b64decode(data))

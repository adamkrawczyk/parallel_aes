from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode

keyFile = open("key.txt", "r")
key = bytes(keyFile.read(), 'utf-8')

dataFile = open("key.txt", "r")
data = bytes(dataFile.read(), 'utf-8')

cipher = AES.new(key[0:-1], AES.MODE_ECB)
cipherText = cipher.encrypt(pad(data[0:-1], AES.block_size))
cipherText = b64encode(cipherText).decode('utf-8')

cipherTextFileECB= open("cipherTextECB.txt", "a")
cipherTextFileECB.write(cipherText)

cipher = AES.new(key[0:-1], AES.MODE_CBC)
cipherText = cipher.encrypt(pad(data[0:-1], AES.block_size))
cipherText = b64encode(cipherText).decode('utf-8')

cipherTextFileCBC= open("cipherTextCBC.txt", "a")
cipherTextFileCBC.write(cipherText)
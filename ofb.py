from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import codecs
from cbc import read, write, getKey # todo: move here 

plainText = read("input.txt", "r")
key = getKey("key.txt")

def ofbEnc(plainText, key):
    pos = 0
    cipherTextChunks = []
    iv = get_random_bytes(16)
    originalIV = iv
    cipher = AES.new(key, AES.MODE_ECB)

    if len(plainText) % 16 != 0:
        plainText += b"1"
    while len(plainText) % 16 != 0:
        plainText += b"0"

    while pos + 16 <= len(plainText):
        toXor = cipher.encrypt(iv)
        nextPos = pos + 16
        toEnc = plainText[pos:nextPos]
        cipherText = bytes([toXor[i] ^ toEnc[i] for i in range(16)])
        cipherTextChunks.append(cipherText)
        pos += 16
        iv = toXor
    return (originalIV, cipherTextChunks)

def ofbDec(cipherTextChunks, key, iv):
    plainText = b""
    cipher = AES.new(key, AES.MODE_ECB)
    for chunk in cipherTextChunks:
        toXor = cipher.encrypt(iv)
        plainText += bytes([toXor[i] ^ chunk[i] for i in range(15)])
        iv = toXor
    while plainText[-1] == 48:
        plainText = plainText[0:-1]
    if plainText[-1] == 49:
        plainText = plainText[0:-1]
    return plainText

iv, result = ofbEnc(plainText, key)

def encryptFromFile(inputFilename, keyFilename):
    plainText = read(inputFilename, "r")
    key = getKey(keyFilename)
    iv, encrypted = ofbEnc(plainText, key)
    write("encrypted_ofb.txt", encrypted)
    write("if_ofb.txt", iv)

def decryptFromFile(encryptedFilename, keyFilename):
    cyphertext = read(encryptedFilename, "rb")
    key = getKey(keyFilename)
    iv = read("if_ofb.txt", "rb")
    decrypted = ofbDec(cyphertext, key, iv)
    write("decrypted_ofb.txt", decrypted)
    print("Atšifrēja OFB: " + codecs.decode(decrypted))

# encryptFromFile("input.txt", "key.txt")
# decryptFromFile("encrypted_ofb.txt", "key.txt")

plain = ofbDec(result, key, iv)
print("Atšifrēja OFB: " + codecs.decode(plain))
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import codecs
# izmantoju funkcijas no iepriekšēja mājas darba daļas - faila cbc; 
# ir viens mīnuss - tas, importējot, izpildīsies; izpildīs savu CBC piemēru
# un izdrukās "Atšifrēja: " - tam nav jāpieverš uzmanība
# īstais OFB atšifrējums sāksies ar "Atšifrēja OFB: "
# (skaidrībai var aizkomentēt cbc.py pēdējas divas rindiņas failā)

from cbc import read, write, getKey, pad, unpad, split_to_blocks, xor

def ofbEnc(plainText, key):
    pos = 0
    cipherTextChunks = []
    iv = get_random_bytes(16)
    originalIV = iv
    cipher = AES.new(key, AES.MODE_ECB)
    plainText = pad(plainText)
    blocks = split_to_blocks(plainText)

    for block in blocks:
        toXor = cipher.encrypt(iv)
        toEnc = block
        cipherText = xor(toXor, toEnc)
        cipherTextChunks.append(cipherText)
        iv = toXor

    return (originalIV, cipherTextChunks)

def ofbDec(cipherTextChunks, key, iv):
    plainText = b""
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = split_to_blocks(cipherTextChunks)
    for chunk in blocks:
        toXor = cipher.encrypt(iv)
        plainText += xor(toXor, chunk)
        iv = toXor

    return unpad(plainText)

def encryptFromFile(inputFilename, keyFilename):
    plainText = read(inputFilename, "r")
    key = getKey(keyFilename)
    iv, encrypted = ofbEnc(plainText, key)
    encrypted = b''.join(encrypted)
    write("encrypted_ofb.txt", encrypted)
    write("if_ofb.txt", iv)

def decryptFromFile(encryptedFilename, keyFilename):
    cyphertext = read(encryptedFilename, "rb")
    key = getKey(keyFilename)
    iv = read("if_ofb.txt", "rb")
    decrypted = ofbDec(cyphertext, key, iv)
    write("decrypted_ofb.txt", decrypted)
    print("Atšifrēja OFB: " + codecs.decode(decrypted))

encryptFromFile("input.txt", "key.txt")
decryptFromFile("encrypted_ofb.txt", "key.txt")
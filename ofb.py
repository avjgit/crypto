from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import codecs
# izmantoju funkcijas no iepriekšēja mājas darba daļas - faila cbc; 
# ir viens mīnuss - tas, importējot, izpildīsies; izpildīs savu CBC piemēru
# un izdrukās "Atšifrēja: " - tam nav jāpieverš uzmanība
# īstais OFB atšifrējums sāksies ar "Atšifrēja OFB: "
# (skaidrībai var aizkomentēt cbc.py pēdējas divas rindiņas failā)

from cbc import read, write, getKey, split_to_blocks

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
    blocks = split_to_blocks(cipherTextChunks)
    for chunk in blocks:
        toXor = cipher.encrypt(iv)
        plainText += bytes([toXor[i] ^ chunk[i] for i in range(15)])
        iv = toXor
    while plainText[-1] == 48:
        plainText = plainText[0:-1]
    if plainText[-1] == 49:
        plainText = plainText[0:-1]
    return plainText

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
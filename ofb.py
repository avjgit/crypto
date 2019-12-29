from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

plainText = b"Lorem ipsum dolor sit amet, consectetur adipiscing e"
key = b"ANAAREMEREAAAAAA"

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
print(iv, result)

plain = ofbDec(result, key, iv)
print(plain)
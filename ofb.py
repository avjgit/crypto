from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import codecs

# izmantoju funkcijas no iepriekšēja mājas darba daļas - faila cbc.py
# to importējot, tas izpildīsies un izdrukās "Atšifrēja: " ar CBC piemēru 
# lai to novērst var cbc.py pēdējas divas rindiņas aizkomentēt
# vai pirms viņām ierakstīt `if __name__ == "__main__":`
# laboto failu nesūtu, lai nebūtu sajaukumu
from cbc import read, write, getKey, pad, unpad, split_to_blocks, xor

def ofbEnc(plainText, key):
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

    write("encrypted_ofb.txt", b''.join(cipherTextChunks))
    write("if_ofb.txt", originalIV)

def ofbDec(cyphertext, key, iv):
    plainText = b""
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = split_to_blocks(cyphertext)
    for chunk in blocks:
        toXor = cipher.encrypt(iv)
        plainText += xor(toXor, chunk)
        iv = toXor
    decrypted = unpad(plainText)
    write("decrypted_ofb.txt", decrypted)
    print("Atšifrēja OFB: " + codecs.decode(decrypted))

ofbEnc(
    plainText=read("input.txt", "r"), 
    key=getKey("key.txt"))

ofbDec(
    cyphertext = read("encrypted_ofb.txt", "rb"), 
    key = getKey("key.txt"), 
    iv = read("if_ofb.txt", "rb"))
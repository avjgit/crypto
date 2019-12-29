from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import codecs

# izmantoju funkcijas no iepriekšēja mājas darba daļas - faila cbc.py
# to importējot, tas izpildīsies un izdrukās "Atšifrēja: " ar CBC piemēru 
# tam nav jāpieverš uzmanība; OFB piemērs drukās "Atšifrēja OFB: "
# bet tīrībai var to arī novērst, cbc.py pēdējas divas rindiņas aizkomentējot
# vai pirms viņām ierakstot `if __name__ == "__main__":`
# laboto failu nesūtu, lai nebūtu sajaukumu
from cbc import read, write, getKey, pad, unpad, split_to_blocks, xor

# Priekšnoteikumi: Python (sk. CBC.py sīkāk)
# Kā izmantot: līdzīgi kā iepriekšējā CBC.py, 
# šajā OFB.py beigās ir divi funkciju izsaukumi - encrypt, decrypt
# var lietot kopā, var atsevišķi.
# Atšķirībā no CBC, šeit vienkāršoju un saīsināju kodu,
# izņēmu, droši vien, nevajadzīgo konstantes
# un to vietā padodot hardkodētus failu nosaukumus;
# arī mazāk funkciju - saglabāšanu failos ieliku algoritmu funkcijās
# Beigu rezultāts - divas funkcijas (encrypt, decrypt) un viņu izsaukumi

def encrypt_ofb(plainText, key):
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

def decrypt_ofb(cyphertext, key, iv):
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

encrypt_ofb(
    plainText = read("input.txt", "r"), 
    key = getKey("key.txt"))

decrypt_ofb(
    cyphertext = read("encrypted_ofb.txt", "rb"), 
    key = getKey("key.txt"), 
    iv = read("if_ofb.txt", "rb"))
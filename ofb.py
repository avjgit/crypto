from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import codecs

# izmantoju funkcijas no iepriekšēja mājas darba daļas - faila cbc.py
# to importējot, tas izpildīsies un izdrukās "Atšifrēja: " ar CBC piemēru 
# tam nav jāpieverš uzmanība; OFB piemērs drukās "Atšifrēja OFB: "
# bet tīrībai var to arī novērst, cbc.py pēdējas divas rindiņas aizkomentējot
# vai pirms viņām ierakstot `if __name__ == "__main__":`
# varēja arī vēl uzlabot, iznesot ārā kopīgas lietas,
# un dažus mainīgos būtu pārsaucis utt.
# tomēr laboto failu nesūtu, lai nebūtu sajaukumu
# un šo jaunu OFB centos izveidot pēc iespējas līdzīgu CBC.py,
# ērtākai salīdzināšanai un starpības saprašanai
from cbc import read, write, getKey, pad, unpad, split_to_blocks, xor

# Priekšnoteikumi: Python (sk. CBC.py sīkāk)
# Kā izmantot: līdzīgi kā iepriekšējā CBC.py, 
# šajā OFB.py beigās ir divi funkciju izsaukumi - 
# encrypt, decrypt; var lietot kopā, var atsevišķi.
# Jāizpilda, ievietojot vienā direktorijā ar CBC.py
# Jābūt arī input.txt un key.txt
# Atšķirībā no CBC, šeit vienkāršoju un saīsināju kodu,
# izņēmu, droši vien, nevajadzīgo konstantes
# un to vietā padodot hardkodētus failu nosaukumus;
# arī mazāk funkciju - saglabāšanu failos ieliku algoritmu funkcijās
# Beigu rezultāts - divas funkcijas (encrypt, decrypt) un viņu izsaukumi

def encrypt_ofb(plainText, key):
    # komentēšu lietas, kas atšķiras no CBC; cipher utml ir tāds pats kā CBC
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = b''

    # atšķirībā no CBC, OFB ir gadījuma IV katrai šifrēšanai
    prev_block = get_random_bytes(16) # "iepriekšējais bloks" ir inicializācijas vektors
    write("iv_ofb.txt", prev_block)

    blocks = split_to_blocks(pad(plainText)) # šeit "bloki" ir plain teksta gabali
    for block in blocks:
        # atšķirībā no CBC, kas XORo, tad iešifrē
        # OFB sākumā iešifrē (pie tam IV, ne plaintext), tikai tad XORo
        to_xor = cipher.encrypt(prev_block)
        encrypted += xor(to_xor, block)
        prev_block = to_xor
    return encrypted

def decrypt_ofb(cyphertext, key, prev_block):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = b''
    blocks = split_to_blocks(cyphertext)
    for block in blocks:
        # OFB, dešifrējot, šifrē! Tad XORo ar šifrētā teksta bloku
        to_xor = cipher.encrypt(prev_block)
        decrypted += xor(to_xor, block)
        prev_block = to_xor
    return unpad(decrypted)

def ofbEncryptFromFile(inputFilename, keyFilename):
    plainText = read(inputFilename, "r")
    ofbKey = getKey(keyFilename)
    encrypted = encrypt_ofb(plainText, ofbKey)
    write("encrypted_ofb.txt", encrypted)

def ofbDecryptFromFile(encryptedFilename, keyFilename, initialVectorFilename):
    cyphertext = read(encryptedFilename, "rb")
    ofbKey = getKey(keyFilename)
    initialVector = read("iv_ofb.txt", "rb")
    decrypted = decrypt_ofb(cyphertext, ofbKey, initialVector)
    write("decrypted_ofb.txt", decrypted)
    # uzreiz izdrukā arī ekrānā ērtākai pārbaudei
    print("Atšifrēja: " + codecs.decode(decrypted))    
    
ofbEncryptFromFile("input.txt", "key.txt")
ofbDecryptFromFile("encrypted_ofb.txt", "key.txt", "iv_ofb.txt")

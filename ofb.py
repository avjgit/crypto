from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from omac import get_omac
import codecs


# izmantoju funkcijas no iepriekšēja mājas darba daļas - faila cbc.py
# to importējot, tas izpildīsies un izdrukās "Atšifrēja: " ar CBC piemēru 
# tam nav jāpieverš uzmanība; OFB piemērs drukās "Atšifrēja OFB: "
# bet tīrībai var to arī novērst, cbc.py pēdējas divas rindiņas aizkomentējot
# vai pirms viņām ierakstot `if __name__ == "__main__":`
# varēja arī vēl uzlabot, iznesot ārā kopīgas lietas,
# un dažus mainīgos būtu pārsaucis utt.
# tomēr laboto cbc.py failu nesūtu, lai nebūtu sajaukumu starp faila versijām;
# un šo jaunu OFB centos izveidot pēc iespējas līdzīgu CBC.py,
# ērtākai salīdzināšanai un starpības saprašanai
from cbc import read, write, getKey, pad, unpad, split_to_blocks, xor

# Priekšnoteikumi: Python (sk. CBC.py sīkāk)
# Kā izmantot: līdzīgi kā iepriekšējā CBC.py, 
# šajā OFB.py beigās ir divi funkciju izsaukumi - 
# encrypt, decrypt; var lietot kopā, var atsevišķi.
# Jāizpilda, ievietojot vienā direktorijā ar CBC.py
# Jābūt arī input.txt, key.txt un key_for_mac.txt

# Atšķirībā no CBC, šeit vienkāršoju un saīsināju kodu,
# izņēmu, droši vien, nevajadzīgas konstantes
# un to vietā padodu hardkodētus failu nosaukumus;

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

def ofbEncryptFromFile(inputFilename, keyFilename, macKeyFilename):
    plainText = read(inputFilename, "r")

    ofbKey = getKey(keyFilename)
    encrypted = encrypt_ofb(plainText, ofbKey)
    write("encrypted_ofb.txt", encrypted)

    macKey = getKey(macKeyFilename)
    mac = get_omac(macKey, plainText)
    write("mac.txt", mac)

def ofbDecryptFromFile(encryptedFilename, initialVectorFilename, keyFilename, macKeyFilename):
    cyphertext = read(encryptedFilename, "rb")
    initialVector = read("iv_ofb.txt", "rb")
    ofbKey = getKey(keyFilename)
    decrypted = decrypt_ofb(cyphertext, ofbKey, initialVector)
    write("decrypted_ofb.txt", decrypted)
    print("Atšifrēja OFB: " + codecs.decode(decrypted))    

    # Pārbauda MAC - vai saņemtais sakrīt ar ģenerēto
    macKey = getKey(macKeyFilename)
    mac_calculated = get_omac(macKey, decrypted)
    mac_received = read("mac.txt", "rb")
    if (mac_received == mac_calculated):
        print("MAC ir korekts")
    else:
        print("MAC nav korekts")

ofbEncryptFromFile("input.txt", "key.txt", "key_for_mac.txt")
ofbDecryptFromFile("encrypted_ofb.txt", "iv_ofb.txt", "key.txt", "key_for_mac.txt")

from Crypto.Cipher import AES
from math import ceil
import codecs

# Kā izmantot:
# - teksts šifrēšanai jāieraksta INPUT_FILE failā
# - atslēga šifrēšanai jāieraksta KEY_FILE failā
# - šā faila beigās atrodas divu funkciju izsaukumi:
#       encryptFromFile(INPUT_FILE, KEY_FILE)
#       decryptFromFile(ENCRYPTED_CBC_FILE, KEY_FILE)
#   tos var laist kopā vai atsevišķi
# --------------------------------------------------
# Priekšnoteikums: uz datora instalēts Python 3
# https://www.python.org/downloads

# Python skriptu var laist no komandrindas vai IDE pēc savas izvēles;
# es izmantoju Visual Studio Code
# https://code.visualstudio.com

# Pamācība kā to pielāgot izstrādei Python valodā:
# https://code.visualstudio.com/docs/languages/python  

BLOCK_SIZE = 16 #šifrēs 16 baitu blokos
INPUT_FILE = "input.txt" # fails ar tekstu iešifrēšanai
KEY_FILE = "key.txt" # fails ar atslēgu
ENCRYPTED_CBC_FILE = "encrypted_cbc.txt" # fails ar iešifrētu ziņu
DECRYPTED_CBC_FILE = "decrypted_cbc.txt" # fails ar dešifrētu ziņu

def pad(data):
    # Šī funkcija papildina tekstu, lai tas var sadalīties BLOCK_SIZE baitu blokos
    # aizpilda nepieciešamus baitus atbilstoši PKCS7 algoritmam
    # https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7

    # izrēķina, kāds ir pēdējā bloka atlikušais garums un nepieciešamais papildinājuma garums
    last_block_length = len(data) % BLOCK_SIZE
    padding_length = BLOCK_SIZE - last_block_length

    # ja papildus baiti nav jāliek, tad jāpieliek vesels bloks :)
    # tas ir nepieciešams lai visu ziņojumu apstrāde notiktu pēc viena un tā paša algoritma
    if padding_length == 0: padding_length = BLOCK_SIZE 

    # izveido papildinājumu, katrā baitā ierakstot ciparu, kas ir klāt pierakstītu baitu skaits;
    # tas vēlāk noderēs papildinātu baitu noņemšanai (sk. "unpad" funkciju zemāk),
    # kas noteiks, cik baitus jānoņem, nolasot ciparu no pēdēja baita
    padding = bytes([padding_length]) * padding_length

    # atgriež tekstu, kas perfekti sadalās vajadzīgajos blokos
    return data + padding

def unpad(data):
    # nosaka, cik baiti jānoņem, nolasot ciparu no pēdēja baita
    padding_length = data[-1]

    # atgriež datus, izņemot papildinājumu
    return data[: -padding_length]

def xor(a, b): 
    # veic XOR katram bitam https://python-reference.readthedocs.io/en/latest/docs/operators/bitwise_XOR.html
    # zip ir funkcija, kas izveido pārus pa elementriem no katra masīva
    # https://www.geeksforgeeks.org/zip-in-python/    
    pairs_of_bits = zip(a, b)
    return bytes([ x^y for (x,y) in pairs_of_bits])

def split_to_blocks(bytestring):
    # Sadala blokos
    number_of_blocks_not_rounded = len(bytestring) / BLOCK_SIZE # Aprēķina bloku skaitu
    number_of_blocks = ceil(number_of_blocks_not_rounded) # Noapaļo bloku skaitu līdz veselajam, uz augšu
    block_numbers = range(number_of_blocks) # masīvs ar bloku kārtas numuriem
    # tagad katram bloka numuram "izgriezīs" atbilstošu bloku,
    # un atgriezīs masīvu ar šiem blokiem
    return [bytestring[BLOCK_SIZE*i : BLOCK_SIZE*(i+1)] for i in block_numbers]

def getKey(keyFilename):
    key = read(keyFilename, "r") # ielasa atslēgu
    return pad(key[:BLOCK_SIZE]) # izmanto atslēgu vinādā garuma ar bloku 

def getCBCIV():
    #initializācijas vektors, BLOCK_SIZE nulles
    return bytearray(BLOCK_SIZE)

def write(filename, content):
    # palīgfunkcijas lasīšanai no/ rakstīšanai failos,
    # lai "nepiesairņotu" algoritma kodu zemāk
    with open(filename, "wb") as outputFile: # saglabā binārajā režīmā ("wb")
        outputFile.write(content)

def read(filename, mode):
    with open(filename, mode) as inputFile:
        content = inputFile.read()
    # ja ielasīts jau baitu režīmā, tad vnk to atgriezt; 
    # ja tas bija teksts, tad to konvertēt baitos
    return content if mode == "rb" else bytes(content, "utf-8")

def encrypt_cbc(plaintext, key):
    # atbilstoši atļaujai uzdevumā, "you may use a function that takes one block as input, performs regular encryption, and returns the encrypted block"
    # šī ir bibliotēkas funkcija, kas vienkārši enkriptē vienu bloku (ECB režīmā)
    cipher = AES.new(key, AES.MODE_ECB) 

    encrypted = b'' # konteineris rezultāta saglabāšanai
    prev_block = getCBCIV() # inicializācijas vektors, kas pilda neeksistējošā iepriekšējā bloka lomu
    plaintext_padded = pad(plaintext) # papildina tekstu līdz garumam, kas dalās ar bloka izmēru bez atlikuma
    blocks = split_to_blocks(plaintext_padded) # sadala tekstu blokos
    for block in blocks:
        to_encrypt = xor(block, prev_block) # kārtējā bloka XOR ar iepriekšējo
        next_block = cipher.encrypt(to_encrypt) # iešifrē XOR rezultātu

        prev_block = next_block # iešifrēšanas rezultāts izmantošanai nākama bloka XORošanai
        encrypted += next_block # saglabā šifrēšanas rezultātu
    return encrypted

def decrypt_cbc(cyphertext, key):
    # daudzas rindiņas ar analogas atbilstošām rindiņām iešifrēšanā (encrypt_cbc)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = b'' 
    prev_block = getCBCIV()
    blocks = split_to_blocks(cyphertext)
    for block in blocks:
        to_xor = cipher.decrypt(block) # secība apgriezta iešifrēšanai - šeit sākumā bloku dešifrē ...
        decrypted += xor(to_xor, prev_block) # ... un tad veic tā XOR ar iepriekšējo bloku
        prev_block = block
    return unpad(decrypted)

def encryptFromFile(inputFilename, keyFilename):
    # ielasa tekstu un atslēgu šifrēšanai, to iešifrē un ieraksta failā
    plainText = read(inputFilename, "r")
    encrypted = encrypt_cbc(plainText, getKey(keyFilename))
    write(ENCRYPTED_CBC_FILE, encrypted)

def decryptFromFile(encryptedFilename, keyFilename):
    # ielasa šifrēto ziņu un atslēgu, to atšifrē un ieraksta failā
    cyphertext = read(encryptedFilename, "rb")
    decrypted = decrypt_cbc(cyphertext, getKey(keyFilename))
    write(DECRYPTED_CBC_FILE, decrypted)
    # uzreiz izdrukā arī ekrānā ērtākai pārbaudei
    print("Atšifrēja CBC: " + codecs.decode(decrypted))

# (INPUT_FILE, KEY_FILE)
# decryptFromFile(ENCRYPTED_CBC_FILE, KEY_FILE)
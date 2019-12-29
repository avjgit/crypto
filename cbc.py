from Crypto.Cipher import AES
from math import ceil
import codecs


# "The result of decrypted should be saved in binary format."
# un
# "Naturally, decrypting an encrypted string should give back the clear text. "

BLOCK_SIZE = 16 #šifrēs 16 baitu blokos

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

def encrypt_cbc(msg, key):
    result = b''

    # atbilstoši atļaujai uzdevumā, "you may only use a function that takes one block as input, performs regular encryption, and returns the encrypted block"
    # šī ir bibliotēkas funkcija, kas vienkārši enkriptē bloku
    cipher = AES.new(key, AES.MODE_ECB) 

    previous_ctxt_block = bytearray(BLOCK_SIZE) #initializācijas vektors, BLOCK_SIZE nulles
    padded_ptxt = pad(msg)
    blocks = split_to_blocks(padded_ptxt) #calculate the number of blocks I've to iter through
    for block in blocks:
        to_encrypt = xor(block, previous_ctxt_block) #xor a block with IV
        new_ctxt_block = cipher.encrypt(to_encrypt)
        result += new_ctxt_block
        previous_ctxt_block = new_ctxt_block
    return result

def decrypt_cbc(ctxt, key):
    result = b''
    previous_ctxt_block = bytearray(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = split_to_blocks(ctxt)
    for block in blocks:
        to_xor = cipher.decrypt(block)
        result += xor(to_xor, previous_ctxt_block)
        previous_ctxt_block = block
    return unpad(result)

encoded = b''    
with open("input.txt", "r") as inputFile:
    for line_content in inputFile:
        x = encrypt_cbc(bytes(line_content, "utf-8"), bytes("YELLOW SUBMARINE", "utf-8"))
        encoded += x        

with open("encoded.txt", "wb") as out: out.write(encoded)

decodedFromFile = b''
with open("encoded.txt", "rb") as inputFile:
    content = inputFile.read()
    decodedFromFile += decrypt_cbc(content, bytes("YELLOW SUBMARINE", "utf-8"))

with open("decoded.txt", "wb") as out: out.write(decodedFromFile)

decodedString = codecs.decode(decodedFromFile)
print(decodedString, end='') #print the encrypted text in base 64




with open("output.txt", "w") as out: out.write(decodedString)
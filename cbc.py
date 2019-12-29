from Crypto.Cipher import AES
import codecs

BLOCK_SIZE = 16

def pad(data):
    # Šī funkcija papildina tekstu, lai tas var sadalīties BLOCK_SIZE baitu blokos
    # aizpilda nepieciešamus baitus atbilstoši PKCS7 algoritmam,
    # kur katrā baitā ieraksta ciparu, kas ir klāt pierakstītu baitu skaits;
    # tas vēlāk noderēs papildinātu baitu noņemšanai (sk. "unpad" funkciju zemāk),
    # kas noteiks, cik baitus jānoņem, nolasot ciparu no pēdēja baita
    # https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    # ja papildus baiti nav jāliek, tad jāpieliek vesels bloks :)
    # tas ir nepieciešams lai visu ziņojumu apstrāde notiktu pēc viena un tā paša algoritma
    if padding_len == 0: padding_len = BLOCK_SIZE 
    padding = bytes([padding_len]) * padding_len
    return data + padding

def unpad(data):
    padding_length = data[-1]
    return data[: -padding_length]

def bxor(a, b): return bytes([ x^y for (x,y) in zip(a, b)])

def encrypt_aes_128_cbc(msg, key):
    result = b''

    # atbilstoši atļaujai uzdevumā, "use block ciphers from an external library"
    # šī ir bibliotēkas funkcija, kas vienkārši enkriptē bloku
    cipher = AES.new(key, AES.MODE_ECB) 

    previous_ctxt_block = bytearray(BLOCK_SIZE) #initializācijas vektors, BLOCK_SIZE nulles
    padded_ptxt = pad(msg)
    nb_blocks = (int)(len(padded_ptxt) / BLOCK_SIZE) #calculate the number of blocks I've to iter through
    for i in range(nb_blocks):
        to_encrypt = bxor(padded_ptxt[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE], previous_ctxt_block) #xor a block with IV
        new_ctxt_block = cipher.encrypt(to_encrypt)
        result += new_ctxt_block
        previous_ctxt_block = new_ctxt_block
    return result

def decrypt_aes_128_cbc(ctxt, key):
    result = b''
    previous_ctxt_block = bytearray(BLOCK_SIZE)
    blocks = (int)(len(ctxt) / BLOCK_SIZE) #calculate the number of blocks I've to iter through
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(blocks):
        block = ctxt[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
        to_xor = cipher.decrypt(block)
        result += bxor(to_xor, previous_ctxt_block)
        previous_ctxt_block = block
    return unpad(result)

decoded = b''
with open("input.txt", "r") as inputFile:
    for line_content in inputFile:
        # encrypt_CBC(bytes(line_content, "utf-8"), bytes("YELLOW SUBMARINE", "utf-8"))
        x = encrypt_aes_128_cbc(bytes(line_content, "utf-8"), bytes("YELLOW SUBMARINE", "utf-8"))
        decoded += decrypt_aes_128_cbc(x, bytes("YELLOW SUBMARINE", "utf-8"))
decodedString = codecs.decode(decoded)
print(codecs.decode(decoded), end='') #print the encrypted text in base 64

with open("output.txt", "w") as out: out.write(decodedString)
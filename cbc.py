from Crypto.Cipher import AES
import codecs

def pad(plaintext):
    # pkcs7
    padding_len = 16 - (len(plaintext) % 16)
    # the message length is a multiple of the block size
    # we add *a whole new block of padding*
    # (otherwise it would be difficult when removing the padding
    # to guess the padding length)
    if padding_len == 0:
        padding_len = 16
    padding = bytes([padding_len]) * padding_len
    return plaintext + padding

def pkcs7_strip(data):
    padding_length = data[-1]
    return data[:- padding_length]

def bxor(a, b): return bytes([ x^y for (x,y) in zip(a, b)])


# def encrypt_CBC(enc_, key):
#     enc = pad(enc_) # here I pad the text (PCKS#7 way)
#     nb_blocks = (int)(len(enc) / 16) #calculate the number of blocks I've to iter through
#     IV = bytearray(16)
#     cipher = AES.new(key, AES.MODE_ECB)
#     output = b''
#     for i in range(nb_blocks):
#         enc2 = xor_for_char(enc[i * 16:(i + 1) * 16], IV) #xor a block with IV
#         IV = cipher.encrypt(enc2) # set the the IV based on the encryption of the xored text
#         output += IV
#     print(codecs.decode(codecs.encode(output, 'base64')).replace("\n", ""), end='') #print the encrypted text in base 64

def encrypt_aes_128_cbc(msg, key):
    result = b''
    cipher = AES.new(key, AES.MODE_ECB)

    previous_ctxt_block = bytearray(16)
    padded_ptxt = pad(msg)
    nb_blocks = (int)(len(padded_ptxt) / 16) #calculate the number of blocks I've to iter through
    for i in range(nb_blocks):
        to_encrypt = bxor(padded_ptxt[i * 16:(i + 1) * 16], previous_ctxt_block) #xor a block with IV
        new_ctxt_block = cipher.encrypt(to_encrypt)
        result += new_ctxt_block
        previous_ctxt_block = new_ctxt_block
    return result

def decrypt_aes_128_cbc(ctxt, key):
    result = b''
    previous_ctxt_block = bytearray(16)
    blocks = (int)(len(ctxt) / 16) #calculate the number of blocks I've to iter through
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(blocks):
        block = ctxt[i * 16:(i + 1) * 16]
        to_xor = cipher.decrypt(block)
        result += bxor(to_xor, previous_ctxt_block)
        # for the next iteration
        previous_ctxt_block = block
    return pkcs7_strip(result)

decoded = b''
with open("input.txt", "r") as inputFile:
        for line_content in inputFile:
            # encrypt_CBC(bytes(line_content, "utf-8"), bytes("YELLOW SUBMARINE", "utf-8"))
            x = encrypt_aes_128_cbc(bytes(line_content, "utf-8"), bytes("YELLOW SUBMARINE", "utf-8"))
            decoded += decrypt_aes_128_cbc(x, bytes("YELLOW SUBMARINE", "utf-8"))
decodedString = codecs.decode(decoded)
print(codecs.decode(decoded), end='') #print the encrypted text in base 64

with open("output.txt", "w") as out: out.write(decodedString)
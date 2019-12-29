from Crypto.Cipher import AES
import codecs

def pad(plaintext):
    # print(plaintext)
    padding_len = 16 - (len(plaintext) % 16)
    # print(padding_len)
    if padding_len == 0:
        padding_len = 16
    # padd = chr(padding_len) * padding_len
    # print(padd)
    # padding = bytes(padd, 'utf8')
    # return plaintext + padding
    padding = bytes([padding_len]) * padding_len
    return plaintext + padding

def pkcs7_padding(message, block_size):
    padding_length = block_size - ( len(message) % block_size )
    # the message length is a multiple of the block size
    # we add *a whole new block of padding*
    # (otherwise it would be difficult when removing the padding
    # to guess the padding length)
    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding

def pkcs7_strip(data):
    padding_length = data[-1]
    return data[:- padding_length]

def xor_for_char(input_bytes, key_input):
    index = 0
    output_bytes = b''
    for byte in input_bytes:
        if index >= len(key_input):
            index = 0
        output_bytes += bytes([byte ^ key_input[index]])
        index += 1
    return output_bytes

def bxor(a, b):
    "bitwise XOR of bytestrings"
    return bytes([ x^y for (x,y) in zip(a, b)])


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
        to_encrypt = xor_for_char(padded_ptxt[i * 16:(i + 1) * 16], previous_ctxt_block) #xor a block with IV
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
        result += xor_for_char(to_xor, previous_ctxt_block)
        # for the next iteration
        previous_ctxt_block = block
    return pkcs7_strip(result)

f = open("input.txt", "r")
if f.mode == 'r':
    content = f.readlines()
    for line_content in content:
        # encrypt_CBC(bytes(line_content, "utf-8"), bytes("YELLOW SUBMARINE", "utf-8"))
        x = encrypt_aes_128_cbc(bytes(line_content, "utf-8"), bytes("YELLOW SUBMARINE", "utf-8"))
        de = decrypt_aes_128_cbc(x, bytes("YELLOW SUBMARINE", "utf-8"))
        print(codecs.decode(de), end='') #print the encrypted text in base 64
f.close()
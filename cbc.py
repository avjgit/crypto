from sys import argv
from Crypto.Cipher import AES
import codecs

def __pad(text):
    text_length = len(text)
    amount_to_pad = 16 - (text_length % 16)
    if amount_to_pad == 0:
        amount_to_pad = 16
    self.pad = chr(amount_to_pad)
    return text + self.pad * amount_to_pad

def pad(plaintext):
    print(plaintext)
    padding_len = 16 - (len(plaintext) % 16)
    print(padding_len)
    if padding_len == 0:
        padding_len = 16
    # padd = chr(padding_len) * padding_len
    # print(padd)
    # padding = bytes(padd, 'utf8')
    # return plaintext + padding
    padding = bytes([padding_len]) * padding_len
    return plaintext + padding

def xor_for_char(input_bytes, key_input):
    index = 0
    output_bytes = b''
    for byte in input_bytes:
        if index >= len(key_input):
            index = 0
        output_bytes += bytes([byte ^ key_input[index]])
        index += 1
    return output_bytes

def encrypt_CBC(enc_, key):
    enc = pad(enc_) # here I pad the text (PCKS#7 way)
    nb_blocks = (int)(len(enc) / 16) #calculate the number of blocks I've to iter through
    IV = bytearray(16)
    cipher = AES.new(key, AES.MODE_ECB)
    output = b''
    for i in range(nb_blocks):
        enc2 = xor_for_char(enc[i * 16:(i + 1) * 16], IV) #xor a block with IV
        IV = cipher.encrypt(enc2) # set the the IV based on the encryption of the xored text
        output += IV
        # print(IV)
    print(codecs.decode(codecs.encode(output, 'base64')).replace("\n", ""), end='') #print the encrypted text in base 64

f = open("input.txt", "r")
if f.mode == 'r':
    content = f.readlines()
    for line_content in content:
        encrypt_CBC(bytes(line_content, "utf-8"), bytes("YELLOW SUBMARINE", "utf-8"))
f.close()
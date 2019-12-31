
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from cbc import read, write, getKey
import codecs


const_zero = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
const_rb = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x87"

CONST_ZERO = 0x00000000000000000000000000000000
CONST_RB = 0x00000000000000000000000000000087

# print((CONST_ZERO).to_bytes(16, byteorder='big'))
# print((CONST_RB).to_bytes(16, byteorder='big'))
cipher = AES.new(getKey("key.txt"), AES.MODE_ECB) 
L = cipher.encrypt(const_zero)
print(L)

def generate_subkeys(key):
#    Algoritms ar komentāriem no https://www.ietf.org/rfc/rfc4493.txt 
#    Section 2.3.  Subkey Generation Algorithm
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +                    Algorithm Generate_Subkey                      +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +   Input    : K (128-bit key)                                      +
#    +   Output   : K1 (128-bit first subkey)                            +
#    +              K2 (128-bit second subkey)                           +
#    +-------------------------------------------------------------------+
#    +   Constants: const_Zero is 0x00000000000000000000000000000000     +
#    +              const_Rb   is 0x00000000000000000000000000000087     +
#    +   Variables: L          for output of AES-128 applied to 0^128    +
#    +                                                                   +
#    +   Step 1.  L := AES-128(K, const_Zero);                           +
#    +   Step 2.  if MSB(L) is equal to 0                                +
#    +            then    K1 := L << 1;                                  +
#    +            else    K1 := (L << 1) XOR const_Rb;                   +
#    +   Step 3.  if MSB(K1) is equal to 0                               +
#    +            then    K2 := K1 << 1;                                 +
#    +            else    K2 := (K1 << 1) XOR const_Rb;                  +
#    +   Step 4.  return K1, K2;                                         +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    const_zero = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    const_rb = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x87"
    cipher = AES.new(key, AES.MODE_ECB) 

#    In step 1, AES-128 with key K is applied to an all-zero input block.
    L = cipher.encrypt(const_zero)
#    In step 2, K1 is derived through the following operation:
#       If the most significant bit of L is equal to 0, 
#       K1 is the left-shift of L by 1 bit.
#       Otherwise, K1 is the exclusive-OR of 
#       const_Rb and the left-shift of L by 1 bit.

#    In step 3, K2 is derived through the following operation:
#       If the most significant bit of K1 is equal to 0, 
#       K2 is the left-shift of K1 by 1 bit.
#       Otherwise, K2 is the exclusive-OR of 
#       const_Rb and the left-shift of K1 by 1 bit.

    print(L)
    # return k1, k2


def get_omac():
    # Divide message into b-bit blocks m = m1 ∥ ... ∥ mn−1 ∥ mn, where m1, ..., mn−1 are complete blocks. (The empty message is treated as one incomplete block.)
    # If mn is a complete block then mn′ = k1 ⊕ mn else mn′ = k2 ⊕ (mn ∥ 10...02).
    # Let c0 = 00...02.
    # For i = 1, ..., n − 1, calculate ci = Ek(ci−1 ⊕ mi).
    # cn = Ek(cn−1 ⊕ mn′)
    # Output t = msbℓ(cn).

    # K1 is used for the case where the length of 
    # the last block is equal to the block length.  K2 is used for the case
    # where the length of the last block is less than the block length.

    return "333beaa54a0dd3ab411a6352dd949601"

def test_subkeys():
    # https://en.wikipedia.org/wiki/One-key_MAC
    # As a small example, suppose b = 4, C = 00112, and k0 = Ek(0) = 01012. Then k1 = 10102 and k2 = 0100 ⊕ 0011 = 01112.
    try:
        assert get_omac() == get_mac_from_library(
        plainText = read("input.txt", "r"), 
        key = getKey("key.txt"))
    except:
        print("test FAILED")
        return
    print("test PASSED!") #ja tiek līdz šai rindiņai, tad assert ir veiksmīgs - savādāk uz assert būtu "nokritis" un neietu tālāk


def get_mac_from_library(plainText, key):
    lib_cmac = CMAC.new(key, ciphermod=AES)
    lib_cmac.update(plainText)
    return lib_cmac.hexdigest()

# pārbaudīt MAC, salīdzinot pašrēķināto ar ārējas bibliotēkas rēķināto
# ja tests neveiksmīgs, tad tālāk izpilde neiet
assert get_omac() == get_mac_from_library(
        plainText = read("input.txt", "r"), 
        key = getKey("key.txt"))

generate_subkeys(getKey("key.txt"))
print("all is fine, all tests PASSED!") 

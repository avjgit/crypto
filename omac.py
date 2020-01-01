from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from cbc import read, write, getKey, xor, split_to_blocks
import codecs
from math import ceil

def generate_subkeys(key_K):
#    Algoritms no https://www.ietf.org/rfc/rfc4493.txt Section 2.3.  Subkey Generation Algorithm
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

    CONST_ZERO_RFC  = 0x00000000000000000000000000000000
    CONST_RB_RFC    = 0x00000000000000000000000000000087

    const_Zero = CONST_ZERO_RFC.to_bytes(16, byteorder='big')
    const_Rb = CONST_RB_RFC.to_bytes(16, byteorder='big')

#    Komentāri no https://www.ietf.org/rfc/rfc4493.txt Section 2.3.  Subkey Generation Algorithm
#    In step 1, AES-128 with key K is applied to an all-zero input block.
    cipher = AES.new(key_K, AES.MODE_ECB)
    L = cipher.encrypt(const_Zero)

#    In step 2, K1 is derived through the following operation:
#       If the most significant bit of L is equal to 0,
    if (L[0] & 0b10000000) == 0:
#       K1 is the left-shift of L by 1 bit.
        K1 = (int.from_bytes(L,"big") << 1).to_bytes(17,"big")[1:]
    else:
#       Otherwise, K1 is the exclusive-OR of
#       const_Rb and the left-shift of L by 1 bit.
        K1 = xor((int.from_bytes(L,"big") << 1).to_bytes(17,"big")[1:],const_Rb)
# šeit no koda viedokļa būtu īsāk sākuma veikt nobīdi - tā vajadzīga jebkura gadījumā,
# tad pārbaudīt L svarīgāko bitu, un tad veikt XOR ja tas bits nav 0 -
# bet saglabāju loģiku burtiski kā RFC algoritmā

# Ja vienkārši konvertēt int uz 16 baitiem, tad var gadīties kļūda
# OverflowError: int too big to convert
# tad jākonvertē uz 17 baitiem, bet jāņem 16, izņemot pirmo

#    In step 3, K2 is derived through the following operation:
#       If the most significant bit of K1 is equal to 0,
#       K2 is the left-shift of K1 by 1 bit.
#       Otherwise, K2 is the exclusive-OR of
#       const_Rb and the left-shift of K1 by 1 bit.

    if (K1[0] & 0b10000000) == 0:
        K2 = (int.from_bytes(K1,"big") << 1).to_bytes(17,"big")[1:]
    else:
        K2 = xor((int.from_bytes(K1,"big") << 1).to_bytes(17,"big")[1:],const_Rb)

# Atkal - loģika tā pati, kā K1 aprēķinā (tikai te L vietā ir K1),
# varētu iznest atsevišķajā funkcijā, bet atstāju vienkāršībai un ērtākai sekošanai
    return K1, K2

def get_omac(key_K, message_M):
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +                   Algorithm AES-CMAC                              +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +   Input    : K    ( 128-bit key )                                 +
#    +            : M    ( message to be authenticated )                 +
#    +            : len  ( length of the message in octets )             +
#    +   Output   : T    ( message authentication code )                 +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +   Constants: const_Zero is 0x00000000000000000000000000000000     +
#    +              const_Bsize is 16                                    +
#    +                                                                   +
#    +   Variables: K1, K2 for 128-bit subkeys                           +
#    +              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
#    +              M_last is the last block xor-ed with K1 or K2        +
#    +              n      for number of blocks to be processed          +
#    +              r      for number of octets of last block            +
#    +              flag   for denoting if last block is complete or not +
#    +                                                                   +
#    +   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
#    +   Step 2.  n := ceil(len/const_Bsize);                            +
#    +   Step 3.  if n = 0                                               +
#    +            then                                                   +
#    +                 n := 1;                                           +
#    +                 flag := false;                                    +
#    +            else                                                   +
#    +                 if len mod const_Bsize is 0                       +
#    +                 then flag := true;                                +
#    +                 else flag := false;                               +
#    +                                                                   +
#    +   Step 4.  if flag is true                                        +
#    +            then M_last := M_n XOR K1;                             +
#    +            else M_last := padding(M_n) XOR K2;                    +
#    +   Step 5.  X := const_Zero;                                       +
#    +   Step 6.  for i := 1 to n-1 do                                   +
#    +                begin                                              +
#    +                  Y := X XOR M_i;                                  +
#    +                  X := AES-128(K,Y);                               +
#    +                end                                                +
#    +            Y := M_last XOR X;                                     +
#    +            T := AES-128(K,Y);                                     +
#    +   Step 7.  return T;                                              +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# In step 1, subkeys K1 and K2 are derived from K through the subkey
# generation algorithm.
    CONST_ZERO_RFC  = 0x00000000000000000000000000000000
    const_Zero = CONST_ZERO_RFC.to_bytes(16, byteorder='big')
    const_Bsize = 16
    K1, K2 = generate_subkeys(key_K)

# In step 2, the number of blocks, n, is calculated.  The number of
# blocks is the smallest integer value greater than or equal to the
# quotient determined by dividing the length parameter by the block
# length, 16 octets.
    n = ceil(len(message_M)/const_Bsize)

    message_blocks = split_to_blocks(message_M)

# In step 3, the length of the input message is checked.  If the input
# length is 0 (null), the number of blocks to be processed shall be 1,
# and the flag shall be marked as not-complete-block (false).
# Otherwise, if the last block length is 128 bits, the flag is marked
# as complete-block (true); else mark the flag as not-complete-block (false).
    if n == 0:
        n = 1
        message_blocks.append(b"")
        flag = False
    else:
        if (len(message_M) % const_Bsize) == 0:
            flag = True
        else:
            flag = False

# In step 4, M_last is calculated by exclusive-OR'ing M_n and one of
# the previously calculated subkeys.  If the last block is a complete
# block (true), then M_last is the exclusive-OR of M_n and K1.
# Otherwise, M_last is the exclusive-OR of padding(M_n) and K2.
    if flag == True:
        M_last = xor(message_blocks[n-1], K1)
    else:
        # padding(x) is the concatenation of x and a single '1',
        # followed by the minimum number of '0's, so that the total length is equal to 128 bits.
        # (te - līdz 16 bitiem (len(message_blocks[n-1])), jo papildina tikai pēdējo bloku)
        padding = b"\x80" + b"\x00"*(const_Bsize - len(message_blocks[n-1]) - 1 ) 
        M_last = xor((message_blocks[n-1] + padding), K2)

# In step 5, the variable X is initialized.
    X = const_Zero

# In step 6, the basic CBC-MAC is applied to M_1,...,M_{n-1},M_last.
    cipher = AES.new(key_K, AES.MODE_ECB)

    for i in range(n-1):
        Y = xor(X, message_blocks[i])
        X = cipher.encrypt(Y)
    
    Y = xor(M_last, X)
    T = cipher.encrypt(Y)
    
# In step 7, the 128-bit MAC, T := AES-CMAC(K,M,len), is returned.
    return T

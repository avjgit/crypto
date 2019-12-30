# https://www.ietf.org/rfc/rfc4493.txt
# 2.  Specification of AES-CMAC
# https://en.wikipedia.org/wiki/One-key_MAC

from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from cbc import read, write, getKey





def get_omac():
    return "333beaa54a0dd3ab411a6352dd949601"

def test():
    def get_mac_from_library(plainText, key):
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(plainText)
        mac_from_library = cobj.hexdigest()
        print(mac_from_library)
        return mac_from_library

    try:
    # pārbaudīt MAC, salīdzinot ar ārējas bibliotēkas rēķināto
        assert get_omac() == get_mac_from_library(
        plainText = read("input.txt", "r"), 
        key = getKey("key.txt"))
    except:
        print("test FAILED")
        return
    print("test PASSED!") #ja tiek līdz šai rindiņai, tad assert ir veiksmīgs - savādāk uz assert būtu "nokritis" un neietu tālāk

test()
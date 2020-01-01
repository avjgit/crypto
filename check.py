const_Bsize = 6
mlen = 2

print(b"\x80" + b"\x00"*(const_Bsize - mlen - 1 ))
print(bytes(1) + bytes(0)*(const_Bsize - mlen - 1 ))
print(bytes([1])*4)
print(bytes(0))
print(bytes(4))
print(chr(128))

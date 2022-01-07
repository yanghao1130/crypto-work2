str1="YELLOW SUBMARINE"
str2="YELLOW SUBMARINE\x04\x04\x04\x04"
len1=len(str1)
padlen=20
padstr=padlen-len1
while len1<padlen:
    str1+=str(chr(padstr))
    len1=len(str1)
print(str1)
print(str1==str2)

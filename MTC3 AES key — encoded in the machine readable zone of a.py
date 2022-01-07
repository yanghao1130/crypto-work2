import hashlib
import codecs
from Crypto.Cipher import AES
import binascii
import base64

def jiaoyan(x):
    k = []
    a = bin(int(x,16))[2:]
    #print(len(a))
    for i in range(0,len(a),8):
        if (a[i:i+7].count("1"))%2 == 0:
            k.append(a[i:i+7])
            k.append('1') 
        else :
            k.append(a[i:i+7])
            k.append('0')      
    a1 = hex(int(''.join(k),2))
    #print("this is " + x + "---" +a1)
    return a1[2:] 

a = [1,1,1,1,1,6]
b = [7,3,1,7,3,1]
c=0
for i in range(0,6):
    c = c + a[i]*b[i]
    res = c % 10
#print (res)  res=7

text1='12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4'
text=text1[0:10]+text1[13:20]+text1[21:28]
textsha1 = hashlib.sha1(text.encode()).hexdigest()
k_seed = textsha1[:32]# 取前16位

c = '00000001'
d=k_seed+c

h= hashlib.sha1(codecs.decode(d,"hex")).hexdigest()
ka = h[:16]
kb = h[16:32]

k_1 = jiaoyan(ka)
k_2 = jiaoyan(kb)  
key = k_1 + k_2
print("密钥为："+key)

iv=b'\x00'*16
ciphertext='9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gy'+ \
        'f1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHv'+ \
        'hQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'

ciphertext=base64.b64decode(ciphertext)
key=binascii.unhexlify(key)
print(key)

plaintext=AES.new(key,AES.MODE_CBC,iv).decrypt(ciphertext)
print(plaintext)

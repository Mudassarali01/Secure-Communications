from pwn import *
import json
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

def is_padded(msg):
    padding=msg[-msg[-1]:]
    return all(padding[i]==len(padding) for i in range(0,len(padding)))

def decrypt_flag(secret, iv, ciphertext):
    sha1=hashlib.sha1()
    sha1.update(str(secret).encode('ascii'))
    key = sha1.digest()[:16]
    ciphertext=bytes.fromhex(ciphertext)
    iv=bytes.fromhex(iv)
    cipher=AES.new(key, AES.MODE_CBC, iv)
    flag=cipher.decrypt(ciphertext)

    if is_padded(flag):
        return unpad(flag,16).decode('ascii')
    else:
        return flag.decode('ascii')

r=remote("socket.cryptohack.org",13371)
r.recvuntil(b"Intercepted from Alice: ")
fromAlice=json.loads(r.recvuntil(b"}").strip().decode())

p=int(fromAlice['p'],16)
g=int(fromAlice['g'],16)

#Creating private keys
a1=random.randint(g,p-1)
b1=random.randint(g,p-1)

#Creating public keys
A1=pow(g,a1,p)
B1=pow(g,b1,p)

#Sending our created public key to Bob
tosend = f'{{"p": "{hex(p)}", "g": "{hex(g)}", "A": "{hex(A1)}"}}'
r.sendline(tosend.encode())

r.recvuntil(b"Intercepted from Bob: ")
fromBob=json.loads(r.recvuntil(b"}").strip().decode())

#Alice's and Bob's intercepted public keys
A=int(fromAlice['A'],16)
B=int(fromBob['B'],16)

tosend = f'{{"B": "{hex(B1)}"}}'
r.sendline(tosend.encode())

r.recvuntil(b"Intercepted from Alice: ")
fromAlice=json.loads(r.recvuntil(b"}").strip().decode())
r.close()

iv=fromAlice['iv']
encrypted_flag=fromAlice['encrypted_flag']

#Creating our own secret, which will be same as Alice's secret
secret = pow(A,b1,p)

flag=decrypt_flag(secret,iv,encrypted_flag)

print()
print(flag)
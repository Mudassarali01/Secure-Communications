from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
from pwn import remote
import json
from sympy.ntheory.residue_ntheory import discrete_log

def decrypt(secret: int, iv: str, cipher: str):
    sha1 = hashlib.sha1()
    sha1.update(str(secret).encode())
    key = sha1.digest()[:16]
    iv = bytes.fromhex(iv)
    aes = AES.new(key, AES.MODE_CBC, iv)
    cipher = bytes.fromhex(cipher)
    plain = aes.decrypt(cipher)
    plain = unpad(plain, AES.block_size)
    return plain

r = remote("socket.cryptohack.org", 13373)
r.recvuntil(b'Alice: ')
j = json.loads(r.recvline().decode())
p = int(j['p'], 16)
g = int(j['g'], 16)
A = int(j['A'], 16)
r.recvuntil(b'Bob: ')
j = json.loads(r.recvline().decode())
B = int(j['B'], 16)
r.recvuntil(b'Alice: ')
j = json.loads(r.recvline().decode())
iv = j['iv']
cipher = j['encrypted']

# q has small factors
q = 0x72b20ce22e5616f923901a946b02b2ad0417882d9172d88c1940fec763b0cdf02ca5862cfa70e47fb8fd10615bf61187cd564a017355802212a526453e1fb9791014f070d77f8ff4dd54a6d1d58969293734e0b6bc22f3ceea788aa33be35eed4bdc1c8ceb94084399d98e13e69a2b9fa6c5583836a15798ba1a10edd81160a15662cdf587df6b816c570f9b11a466d1b4c328180f614e964f3a5ec61c3f2b759b21687a122f9faefc86fe69a3efd14829639596eb7f2de6eab6b444d06233d34d0651e6fed17db4d0025e58db7cad8824c3e93ed24df588a0a4530be2676e995f870172b9e765ec2886bce140000000000000000000000000000000000000000000000000000000000000000000000000000001
res = {'p': hex(q), 'g': hex(g), 'A': hex(A)}
r.sendline(json.dumps(res).encode())
r.recvuntil(b'you: ')
j = json.loads(r.recvline().decode())
B = int(j['B'], 16)

b = discrete_log(q, B, g)
print(b)
secret = pow(A, b, p)
print(decrypt(secret, iv, cipher).decode())

r.shutdown()
r.close()
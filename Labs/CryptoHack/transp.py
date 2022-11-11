from Crypto.PublicKey import RSA
key = RSA.importKey(open('transparency.pem').read())
print(key.d)

given = "label"
print("crypto{", end="")
for x in given:
  print(chr(ord(x)^13), end="")
print("}")
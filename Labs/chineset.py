congruences = [(2, 5), (3, 11), (5, 17)]
N = 1
for _, m in congruences:
    N *= m

for ct in range(N):
    isSolution = True 
    for n, m in congruences:
        if ct % m != n:
            isSolution = False
    
    if isSolution:
        print(ct)
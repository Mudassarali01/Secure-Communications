import factor


N = 510143758735509025530880200653196460532653147
p, q = factor(N)
print(min(p, q)[0])
import random

def random_line(ffile):
    fline = open(ffile, encoding="latin-1").read().splitlines()
    return random.choice(fline)

g = open ("passwords.txt", "a")
g.write("$Global:Passwords = @('")
for i in range(101):
    fname= random_line("rockyou.txt")

    g.write(fname+"', '")
    print(fname)

g.write(");")
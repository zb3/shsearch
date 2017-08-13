letters = 'qwertyuiopasdfghjklzxcvbnm'
numbers = '0123456789'

ext = '.php'

with open('2letter', 'w') as f:
    for a in letters:
        for b in letters:
            f.write(a+b+ext+'\n')

    for a in letters:
        for b in numbers:
            f.write(a+b+ext+'\n')

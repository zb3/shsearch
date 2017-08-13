import sys

existing = '\n'
output = ''

for idx in range(len(sys.argv)-2):
    with open(sys.argv[idx+1], 'r') as f:
        existing += f.read()+'\n'

with open(sys.argv[len(sys.argv)-1], 'r') as f:
    for item in f:
        item = item.lstrip('/')
        if '\n'+item not in existing and '\n'+item.replace('\n', '/\n') not in existing:
            output += item

with open(sys.argv[len(sys.argv)-1], 'w') as f:
    f.write(output)

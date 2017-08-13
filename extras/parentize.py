import sys
from collections import OrderedDict, deque

existing_dirs = set()
subdirs = {}

existing = '\n'
output = ''
min_subdirs = int(sys.argv)  if len(sys.argv) > 2 else 3


items = []

with open(sys.argv[1], 'r') as f:
    for idx, line in enumerate(f):
        item = line.strip()
        items.append(item)

        if item.endswith('/'):
            existing_dirs.add(item)

        itemdir = item[:-1]
        item = ''

        while '/' in itemdir:
            item += itemdir[:itemdir.index('/')+1]
            itemdir = itemdir[itemdir.index('/')+1:]

            #even if it exists, but the entry in subdirs exists, we still count it
            if item not in existing_dirs and item not in subdirs:
                subdirs[item] = [0, idx]

            if item in subdirs:
                subdirs[item][0] += 1


to_insert = deque()

for d in subdirs:
    if subdirs[d][0] >= min_subdirs:
        print(d, subdirs[d][1])
        to_insert.append((d, subdirs[d][1]))

to_insert.append(None)
to_write = to_insert.popleft()

outitems = []

for idx, item in enumerate(items):
    while to_write and to_write[1] == idx:
        outitems.append(to_write[0])

        to_write = to_insert.popleft()

    outitems.append(item)

outitems = list(OrderedDict.fromkeys(outitems))

with open(sys.argv[1], 'w') as f:
    f.write('\n'.join(outitems)+'\n')


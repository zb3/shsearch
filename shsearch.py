import sys
import threading
import http.client
import urllib.parse
import select
import gzip
import threading
import re
import os
import ssl
import io
import queue
import shlex
import argparse

parser = argparse.ArgumentParser(add_help=False)

parser.add_argument('--help',  action='help', default=argparse.SUPPRESS, help='show this help message and exit')
parser.add_argument('--head', '-h', action='store_true', help='Force head mode even if dictfile has no .head extension.')
parser.add_argument('--num-threads', '-n', type=int, default=5)
parser.add_argument('--ignore-200', action='store_true', help='Don\'t report the 200 OK response, assume we\'ll always get it.')
parser.add_argument('--user-agent', '-u', default='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36')
parser.add_argument('--stop-features', '-s', default='', help='Stop scan if these are found (separated by comma).')
parser.add_argument('--extension', '-e', default='php', help='Extension to substitute %%EXT%% with. Default is %(default)s.')
parser.add_argument('--verbose', '-v', action='store_true', help='Display requested urls.')
parser.add_argument('--no-respect-indexes', action='store_true', help='Ignore "Index of" listings.')
parser.add_argument('--max-dir-depth', '-d', type=int)
parser.add_argument('--no-optimize-subdirs', action='store_true', help='Fetch directories even if we got 404 while fetching parent.')
parser.add_argument('--assume-dirs-exist', action='store_true', help='Don\'t check if directories in rootfile exist.')
parser.add_argument('--verify-certs', action='store_true')
parser.add_argument('--no-display-indexes', '-ni', action='store_true', help='Don\'t show indexes in head mode.')
parser.add_argument('--strip-dir-slashes', '-sd', action='store_true', help='Request directory urls without trailing slashes. With slash redirects, we can discover urls that would only work without that slash and scan directories while using two requests only on successful match.')
parser.add_argument('--no-follow-slash-redirects', action='store_true', help='Don\'t follow redirects that append slash to url. By default, only these redirects are followed.')

parser.add_argument('--header-name', action='append', help='Add HTTP header with this name...')
parser.add_argument('--header', action='append', help='...and this value')

parser.add_argument('--feature', action='append', help='Add a feature with this name...')
parser.add_argument('--feature-regex', action='append', help='...and this regex')

parser.add_argument('--exec-on', action='append', help='If any of these features separated by comma are matched...') #access as exec_on
parser.add_argument('--exec-cmd', action='append', help='...execute this command. This is a shell script and you can use $URL, $PID and $FEATURES.')

parser.add_argument('target', help="Target URL, this must be a directory.")
parser.add_argument('dictfile', nargs='?', default='shells', help='Dictionary file with entries separated by newline and trailing newline. Default is "shells".')
parser.add_argument("rootfile", nargs='?', help='File with root directories relative to the target directory (with trailing newline). Search will be repeated in those directiories which were found.')

args = parser.parse_args()

target = args.target

if not re.match('^[a-z]+://', target):
    target = 'http://'+target

if not target.endswith('/'):
    target += '/'

dictfile = args.dictfile
rootfile = args.rootfile

use_head = dictfile.endswith('.head') or args.head
use_https = target.startswith('https://')

user_agent = args.user_agent
num_threads = args.num_threads
report_200 = not args.ignore_200

headers = {
   'User-Agent': user_agent,
   'Connection': 'keep-alive',
   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
   'Accept-Encoding': 'gzip',
   'Accept-Language': 'en-US,en;q=0.8'
}


if args.header_name and args.header:
    for name, value in zip(args.header_name, args.header):
        headers[name] = value

features = (
    (re.compile('<input'), 'input'),
    (re.compile('<textarea'), 'textarea'),
    (re.compile(r'<input[^<>]*?type\s*=\s*[\'"]?file'), 'upload'),
    (re.compile(r'<input[^<>]*?type\s*=\s*[\'"]?password'), 'password'),
    (re.compile(r'uname -a'), 'uname'),
    (re.compile(r'\b(eval|exec)\b'), 'eval'),
    (re.compile(r'^<?php'), 'php_source')
)

if args.feature and args.feature_regex:
    for name, regex in zip(args.feature, args.feature_regex):
        features.append(re.compile(regex), name)

exec_on_match = {}

if args.exec_cmd and args.exec_on:
    our_pid = str(os.getpid())

    for conditions, command in zip(args.exec_on, args.exec_cmd):
        for condition in conditions.split(','):
            if condition not in exec_on_match:
                exec_on_match[condition] = []

            exec_on_match[condition].append(command.replace('$PID', our_pid))


stop_features = args.stop_features.split(',')
extension = args.extension
respect_indexes = not args.no_respect_indexes
max_dir_depth = args.max_dir_depth
optimize_subdirs = not args.no_optimize_subdirs
disable_cert_verification = not args.verify_certs
assume_dirs_exist = args.assume_dirs_exist
try_show_directory_indexes = not args.no_display_indexes
follow_slash_redirects = not args.no_follow_slash_redirects
strip_dir_slashes = args.strip_dir_slashes
verbose = args.verbose



#############

report_200 = report_200 or use_head
conn_ctx = None
if use_https and disable_cert_verification:
      conn_ctx = ssl.create_default_context()
      conn_ctx.check_hostname = False
      conn_ctx.verify_mode = ssl.CERT_NONE

method = 'GET'
if use_head:
    method = 'HEAD'
tocheck = queue.Queue()
stopped = False
items = []
running_threads = []
queue_lock = threading.Lock()
in_progress = 0
link_pattern = re.compile(r'''<a [^<>]*?href\s*=\s*("[^"]*"|'[^']*'|[^ ])''', re.DOTALL | re.IGNORECASE)
dirs_to_ignore = set()
echo_lock = threading.Lock()
our_pid = str(os.getpid())



def echo(what):
    echo_lock.acquire()
    sys.stdout.write(what+'\n')
    echo_lock.release()

def add_root(url):
    newitems = []
    for kind, path, depth, dep in items:
        newitems.append((kind, url+path, 1, url+dep if dep is not None else None))

    enqueue(newitems)

def enqueue(items):
    global in_progress
    queue_lock.acquire()

    for item in items:
        tocheck.put(item)
        in_progress += 1

    queue_lock.release()

def queue_finish_url():
    global in_progress
    queue_lock.acquire()

    in_progress -= 1

    if tocheck.empty() and not in_progress:
        for _ in range(num_threads):
            tocheck.put(None)

    queue_lock.release()

def ensure_connection(conn, host):
    if conn and conn.sock is not None and select.select([conn.sock], [], [], 0)[0]:
        conn.close()
        conn = None

    if not conn:
        if use_https:
            conn = http.client.HTTPSConnection(host, context=conn_ctx)
        else:
            conn = http.client.HTTPConnection(host)

    return conn

def harvest_links(url, content, raw=False, skip_url=False):
    ret = []

    for match in link_pattern.finditer(content):
        link = match.group(1)

        if link.startswith('"') or link.startswith("'"):
            link = link[1:-1]

        link = urllib.parse.urljoin(url, link)

        if not link.startswith(url):
            continue

        linkpart = link[len(url):]
        if not raw and ('?' in linkpart or '#' in linkpart or '/' in linkpart[:-1]):
            continue

        linkpart = linkpart.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#27;', "'").replace('&amp;', '&')
        if not skip_url:
            ret.append(url+linkpart)
        else:
            ret.append(linkpart)

    return ret

def is_index_of(content):
    if not content:
        return False

    cl = content.lower()

    return 'index of' in cl or '../' in cl or 'parent directory' in cl


def send_request(method, url, headers, shared):
    urlparts = url.split('/', 3)
    conn = shared['conn'] = ensure_connection(shared['conn'], urlparts[2])
    conn.request(method, '/'+urlparts[3], None, headers)
    return conn.getresponse()


def process_item(item, shared):
    kind, url, depth, dep = item
    is_dir = url.endswith('/')

    if optimize_subdirs and dep is not None and dep in dirs_to_ignore:
        if is_dir:
            dirs_to_ignore.add(url)

        return

    if verbose:
        echo(url)


    current_method = method
    if respect_indexes and try_show_directory_indexes and is_dir:
        current_method = 'GET'

    orig_url = url
    if strip_dir_slashes and kind != 'root':
        url = url.rstrip('/')

    res = send_request(current_method, url, headers, shared)

    if follow_slash_redirects and current_method != 'HEAD' and res.status // 100 == 3 and not url.endswith('/') and res.getheader('location') == url+'/':
        res.read()

        url = res.getheader('location')
        res = send_request(current_method, url, headers, shared)
        echo('redirect to '+url)

    content = res.read().decode('iso-8859-1')

    if optimize_subdirs and is_dir and (res.status == 404 or res.status == 401):
        dirs_to_ignore.add(orig_url)

    if res.getheader('content-encoding', None) == 'gzip':
        content = gzip.GzipFile(fileobj=io.StringIO(content)).read()

    if (kind == 'root' or is_dir) and (assume_dirs_exist or (res.status != 401 and (res.status != 404 or url == target))):
        skip = False

        if (kind != 'root' or respect_indexes) and res.status // 100 == 2 and is_index_of(content):
            echo('index: '+url)
            skip = True
            links = harvest_links(url, content)

            if len(links):
                newitems = []

                for link in links:
                    if link.endswith('/'):
                        if not max_dir_depth or depth < max_dir_depth:
                            nkind = kind
                            if use_head:
                                nkind = 'url'

                            newitems.append((nkind, link, depth+1, None))
                    elif not use_head:
                        newitems.append(('url', link, depth+1, None))

                enqueue(newitems)

                if use_head and try_show_directory_indexes:
                    links = harvest_links(url, content, skip_url=True)
                    echo('Index of '+url+':\n'+'\n'.join(links)+'\n')

        if kind == 'root' and not skip:
            add_root(url)

    matched = []
    if res.status // 100 == 2 and report_200:
        matched.append('respOK')

        if current_method == 'GET' and not content:
            matched.append('empty')

    elif res.status // 100 == 3:
        matched.append('redir: '+res.getheader('location',''))
    elif res.status == 403:
        matched.append('resp403')
    elif res.status == 401:
        feature = 'http_auth'
        wwwauth = res.getheader('www-authenticate', None)

        if wwwauth:
            feature += ': '+wwwauth

        matched.append(feature)

    if content:
        for f in features:
            if f[0].search(content):
                matched.append(f[1])

                if f[1] in stop_features:
                    stopped = True

    if len(matched):
        matched_features = ','.join(matched)
        echo(url+': '+matched_features)

        for match in matched:
            match = match.split(':', 1)[0]

            if match in exec_on_match:
                actions = exec_on_match[match]
                quoted_url = shlex.quote(url)

                for action in actions:
                    os.system(action.replace('$URL', quoted_url).replace('$FEATURES', matched_features))



def worker():
    global stopped
    shared = {'conn': None}

    while not stopped:
        item = tocheck.get()

        if item is None:
            break

        try:
            process_item(item, shared)

        except Exception as e:
           raise e
           echo(e)

        queue_finish_url()


def put_dir_dep(deps, cur, prefix=''):
    if cur == '/':
        return None

    if cur.endswith('/'):
        deps.append(cur)
        cur = cur[:-1]

    while '/' in cur:
        cur = cur[:cur.rindex('/')]
        if cur+'/' in deps:
            return prefix+cur+'/'

    return None

"""
reorder so that if X depends on Y, there are at least num_threads-1 items between them, if possible.
this way we can optimize dependent directories, albeit this is not exact, otherwise more code'd be needed
"""
def reorder_items_dirs(input, n):
    dir_ticks = {}

    for x in range(len(input)):
        idx = x

        #while not ready
        while not (input[idx][3] is None or (input[idx][3] in dir_ticks and x-dir_ticks[input[idx][3]]-1 >= n)):
            idx += 1

            if idx >= len(input):
                idx = x
                break

        if idx != x:
            tmp = input[idx]

            for t in range(idx, x, -1):
                input[t] = input[t-1]

            input[x] = tmp

        if input[x][1].endswith('/'):
            dir_ticks[input[x][1]] = x

##

tocheck.put(('root', target, 0, None))
in_progress += 1

if rootfile:
    dirdeps = []
    rootitems = []

    f = open(rootfile, 'r')
    for line in f:
        cur = line.strip().lstrip('/')
        rootitems.append(('root', target+cur, 1, put_dir_dep(dirdeps, cur, target)))
    f.close()

    if optimize_subdirs:
        reorder_items_dirs(rootitems, num_threads)

    for item in rootitems:
        tocheck.put(item)
        in_progress += 1


dirdeps = []

#this is meant to be used only for replacement purposes, this domain has no www
domain = target.split('/', 3)[2].split(':')[0]
ldomain = None

if domain.count(':') > 1 or re.search('[.]\d+$', domain):
    domain = None
else:
    if domain.startswith('www.'):
        domain = domain[4:]

    ldomain = domain.split('.', 1)[0]


f = open(dictfile, 'r')
for line in f:
    cur = line.strip().lstrip('/').replace('%EXT%', extension)
    if domain:
        cur = cur.replace('%LDOMAIN%', ldomain).replace('%DOMAIN%', domain)
    elif '%DOMAIN%' in cur or '%LDOMAIN%' in cur:
        continue

    items.append(('url', cur, 1, put_dir_dep(dirdeps, cur)))
f.close()

if optimize_subdirs:
    reorder_items_dirs(items, num_threads)


for _ in range(num_threads):
    nthread = threading.Thread(target=worker)
    nthread.start()
    running_threads.append(nthread)

for t in running_threads:
    t.join()


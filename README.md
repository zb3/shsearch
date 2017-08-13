# shsearch

**Note**: This readme is not a good one, it doesn't reflect `shsearch` properly. As a developer of `shsearch` I dislike this readme.

What's this? This is a dictionary based HTTP scanner originally made to detect so called "shells" (like WSO, b374k etc), but then extended to support other scenarios.

There are tons of scripts like this, but this one can:
* Analyse content of the respone (via regex, currently we detect only shell-related things like `<input>` of type `file` for example, but you can specify custom regexes)
* Stop / execute shell script when given feature is matched
* Repeat search in multiple directories, only if these directories are found
* Skip items if parent directory is not found (almost, see the source)
* Display indexes if found (`Index Of` detection "needs improvement" though)
* Scan newly found directories (via indexes) recursively (BFS)
* Optionally request directories without a traling `/` while following `/` redirect
* Support `%EXT%` but also `%DOMAIN%` (without www) and `%LDOMAIN%` (leftmost part of the domain without www) substitutions.
* Support changing user agent and custom headers (actually that's trivial)

My intent above is not to say this tool is better, coz some core functionality like for instance stopping/resuming a scan is not implemented here... It just aims to be a relatively lightweight one.

Of course dictionary based tools can only get as good as the dictionaries are, so nothing will help if you don't have a dictionary with a working entry or... what you're looking for is simply not there.


## Using this (simplified version)

First of all, you need a dictionary. There are two dictionaries included in the `dict` directory:

* `shells` dictionary (`shells`, `shells.2`, `shells.3`, `shells.4`, `shells.5` and `shells.6` files)
* `fuzz` dictionary containing generic interesting things (`fuzz.head`, `fuzz.2.head`, `fuzz.3.head`, `fuzz.4.head` and `fuzz.5.head` files)
(I mostly stole those but also added some items and split them into so called "chains" - more on that later)

Well in fact the first thing you need is python 2.7+ or python 3.5+ (no other dependencies). `shsearch.py` is for python 3 and `shsearch2.py` is for ... can you guess? python 4? Nope, try again...

Then:
```
$ python3 shsearch.py TARGET_URL DICT_FILE
```

Optionally you can have a second dictionary which is the root dictionary - those folders will be checked for existence, and if they exist, scan will be repeated there. `dict/some.dirs` file is a sample root dictionary.

```
$ python3 shsearch.py TARGET_URL DICT_FILE ROOT_DICT_FILE
```

### But wait! It will most probably not do what you want...

Normally we use `GET` requests and analyse the content (currently only for "shells"), but in case of the `fuzz` dictionary, we care mostly about the mere presence of those entries. If a file name ends with `.head`, `HEAD` mode will be used.

Also for `GET` mode, if we stumble upon an "Index of" page, all items found there are requested and scanned. For subdirectories, if they don't contain indexes, the whole scan is repeated treating these directories as root urls. This process is by default limited by directory depth, max depth is by default 3.

`HEAD` mode is a bit misleading, because by default we send `GET` requests for entries with a trailing slash (which we treat as directories). We do this because if the response contains a directory index, we'll display it and request all subdirectories found there. Unlike `GET` mode, if that subdirectories have no index, we obviously don't repeat the whole scan there, coz in `HEAD` mode, it's the location that is important, not the content (well I know it's generally not the case, but later analysis is beyond the scope of this tool).

Anonther thing to know is that by default if we get a 404 while requesting a directory (trailing slash), we try to skip all entries that "depend" on the existence of this directory (this can be turned off by the `--no-optimize-subdirs` option). So if `a/` is not found, `a/b/` and  `a/b/c/d/` should be skipped. Since we can only skip entries after we know that it's dependency doesn't exist, entries that depend on X must not preceede X, otherwise this optimization can't be used. Actually this is not enough since this tool is multithreaded, and if there are 5 threads and an entry immediately follows its dependency, then we request it before we get the information about its non-existing dependency. To solve the problem, `shsearch` tries to reorder items so that the distance between an entry and its dependency is at least `N-1`, `N` being the number of threads. That's why entries might not be requested in order, and in theory we may still end up making unnecessary requests (of course I could do it "properly" but this would complicate the code I want to keep simple).

Finally, there are some variable substitutions:
* `%EXT%` is replaced with `php` by default (change this using the `-e` option
* `%DOMAIN%` is replaced with the domain without leading www, so when the domain is `www.a.b.c.d.e.com`, `%DOMAIN%` is replaced with `a.b.c.d.e.com`
* `%LDOMAIN%` is replaced with the leftmost part of the domain without leading www, so when the domain is `www.abc.com.pl`, `%LDOMAIN%` is replaced with `abc`


### A bit about content "features"

Builtin features:
* `respOK` - 1XX or 2XX response
* `empty` - response as above, but there's no content
* `redir: URL` - redirect
* `resp403`
* `http_auth: ...`

Builtin regex features (some):
* `upload` - HTML `input` of type `file`
* `password` - HTML `input` of type `password`
* `php_source` - `<?php`

See the source for more...



### Output
Output is currently optimized for humans... but you can execute a script when a given feature is matched:
```
$ python shsearch.py --exec-on upload --exec-cmd 'echo upload found @ $URL ($FEATURES), pid of shsearch so we can kill it is $PID'
```
If a feature `http_auth: Basic realm="R341M"` is matched, `--exec-on http_auth` will work.


### Slash hack

Entries ending with `/` are treated as directories. So if you wanted to check if a directory `status` exists, you'd have `status/` line in your dictionary file. But if you also wanted to check if `/status` url without a slash returns something, technically you'd need to add `status` to your dictionary too.

However some servers allow requesting directories without the trailing slash - `302` is then returned which is different from `404` so we know something is there. But files only work without the slash, so technically it's more optimal to request directories without the slash and then just follow the `302` redirect. This is what the `--strip-dir-slashes` option does.


## Non-simplified version


```
$ python shsearch.py
usage: shsearch3.py [--help] [--head] [--num-threads NUM_THREADS]
                    [--ignore-200] [--user-agent USER_AGENT]
                    [--stop-features STOP_FEATURES] [--extension EXTENSION]
                    [--verbose] [--no-respect-indexes]
                    [--max-dir-depth MAX_DIR_DEPTH] [--no-optimize-subdirs]
                    [--assume-dirs-exist] [--verify-certs]
                    [--no-display-indexes] [--strip-dir-slashes]
                    [--no-follow-slash-redirects] [--header-name HEADER_NAME]
                    [--header HEADER] [--feature FEATURE]
                    [--feature-regex FEATURE_REGEX] [--exec-on EXEC_ON]
                    [--exec-cmd EXEC_CMD]
                    target [dictfile] [rootfile]

positional arguments:
  target                Target URL, this must be a directory.
  dictfile              Dictionary file with entries separated by newline and
                        trailing newline. Default is "shells".
  rootfile              File with root directories relative to the target
                        directory (with trailing newline). Search will be
                        repeated in those directiories which were found.

optional arguments:
  --help                show this help message and exit
  --head, -h            Force head mode even if dictfile has no .head
                        extension.
  --num-threads NUM_THREADS, -n NUM_THREADS
  --ignore-200          Don't report the 200 response, assume we'll always get it.
  --user-agent USER_AGENT, -u USER_AGENT
  --stop-features STOP_FEATURES, -s STOP_FEATURES
                        Stop scan if these are found (separated by comma).
  --extension EXTENSION, -e EXTENSION
                        Extension to substitute %EXT% with. Default is php.
  --verbose, -v         Display requested urls.
  --no-respect-indexes  Ignore "Index of" listings.
  --max-dir-depth MAX_DIR_DEPTH, -d MAX_DIR_DEPTH
  --no-optimize-subdirs
                        Fetch directories even if we got 404 while fetching
                        parent.
  --assume-dirs-exist   Don't check if directories in rootfile exist.
  --verify-certs
  --no-display-indexes, -ni
                        Don't show indexes in head mode.
  --strip-dir-slashes, -sd
                        Request directory urls without trailing slashes. With
                        slash redirects, we can discover urls that would only
                        work without that slash and scan directories while
                        using two requests only on successful match.
  --no-follow-slash-redirects
                        Don't follow redirects that append slash to url. By
                        default, only these redirects are followed.
  --header-name HEADER_NAME
                        Add HTTP header with this name...
  --header HEADER       ...and this value
  --feature FEATURE     Add a feature with this name...
  --feature-regex FEATURE_REGEX
                        ...and this regex
  --exec-on EXEC_ON     If any of these features separated by comma are
                        matched...
  --exec-cmd EXEC_CMD   ...execute this command. This is a shell script and
                        you can use $URL, $PID and $FEATURES.

```


## Extras

There are some extra tools in the `extras` folder, they helped when building included dictionaries:

* `makechain.py D1 D2 ... DN` - makes `DN` file contain only unique items present in `DN` but not in previous files. This tool overwrites `DN` and tries to preserve the order.

* `parentize.py DICTFILE [N=3]` - if there are at least `N` items that depend on some directory, this tool inserts that dependency before the first dependent item. Duplicate items are then removed.  This tool overwrites `DICTFILE`.

   For example
   ```
   a/b/c/
   a/b/d/
   a/b/t
   e/f/e
   e/f/p
   e/gg/e
   e/gg/r
   e/f/a
   e/
   ```
   
   is turned into
   
   ```
   a/
   a/b/
   a/b/c/
   a/b/d/
   a/b/t
   e/
   e/f/
   e/f/e
   e/f/p
   e/gg/e
   e/gg/r
   e/f/a
   ```
   
   and the optimization mechanism in `shsearch` can now work properly.


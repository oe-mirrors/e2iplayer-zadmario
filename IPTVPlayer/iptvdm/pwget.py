# -*- coding: utf-8 -*-

from __future__ import print_function
try:
    from urllib import urlretrieve as urllib_urlretrieve
except Exception:
    from urllib.request import urlretrieve as urllib_urlretrieve
import sys
import traceback


def formatExceptionInfo(maxTBlevel=1):
    cla, exc, trbk = sys.exc_info()
    excName = cla.__name__
    try:
        excArgs = exc.__dict__["args"]
    except KeyError:
        excArgs = "<no args>"
    excTb = traceback.format_tb(trbk, maxTBlevel)
    cla = None
    exc = None
    trbk = None
    return "%s\n%s\n%s" % (excName, excArgs, excTb)


def download(url, file):
    try:
        (tmpfile, headers) = urllib_urlretrieve(url, file)
        return 0, str(headers)
    except Exception:
        return 2, str(formatExceptionInfo())


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print('Usage: python pwget url file', file=sys.stderr)
        sys.exit(1)

    sts, data = download(sys.argv[1], sys.argv[2])
    print(data, file=sys.stderr)
    sys.exit(sts)

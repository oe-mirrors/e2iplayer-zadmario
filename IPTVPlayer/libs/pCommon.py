# -*- coding: utf-8 -*-

###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _, GetIPTVNotify, GetIPTVSleep
from Plugins.Extensions.IPTVPlayer.tools.iptvtypes import strwithmeta
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc, IsHttpsCertValidationEnabled, byteify, GetDefaultLang, rm, UsePyCurl, GetJSScriptFile, \
                                                        IsExecutable, iptv_system, GetTmpDir
from Plugins.Extensions.IPTVPlayer.components.asynccall import IsMainThread, IsThreadTerminated, SetThreadKillable, iptv_execute
from Plugins.Extensions.IPTVPlayer.tools.e2ijs import js_execute_ext
from Plugins.Extensions.IPTVPlayer.libs import curlimpersonate, ph
from Plugins.Extensions.IPTVPlayer.libs.e2ijson import loads as json_loads, dumps as json_dumps
###################################################
from Plugins.Extensions.IPTVPlayer.p2p3.manipulateStrings import ensure_binary, strDecode, iterDictItems, ensure_str
from Plugins.Extensions.IPTVPlayer.p2p3.UrlParse import urljoin, urlparse, urlunparse
from Plugins.Extensions.IPTVPlayer.p2p3.pVer import isPY2
if isPY2():
    import cookielib
    from httplib import IncompleteRead
    try:
        from cStringIO import StringIO
    except Exception:
        from StringIO import StringIO
else:
    import http.cookiejar as cookielib
    from http.client import HTTPMessage, IncompleteRead
    from io import BytesIO
    basestring = str
    file = open
    unichr = chr
from Components.config import config, ConfigText, configfile
from Plugins.Extensions.IPTVPlayer.p2p3.UrlLib import urllib_addinfourl, urllib_unquote, urllib_unquote_plus, urllib_quote_plus, urllib_urlencode, urllib_quote, \
                                                      urllib2_HTTPRedirectHandler, urllib2_BaseHandler, urllib2_HTTPHandler, urllib2_HTTPError, \
                                                      urllib2_URLError, urllib2_build_opener, urllib2_urlopen, urllib2_HTTPCookieProcessor, \
                                                      urllib2_HTTPSHandler, urllib2_ProxyHandler, urllib2_Request
###################################################
# FOREIGN import
###################################################
import base64
try:
    import ssl
except Exception:
    pass
import os
import random
import re
import tempfile
import time
import unicodedata
import zlib
from shutil import move
import shutil
try:
    from PIL import Image
    hasPIL = True
except Exception:
    hasPIL = False
try:
    import pycurl
except Exception:
    pass
try:
    import gzip
except Exception:
    pass
from binascii import hexlify
###################################################

# Query/form fields that carry a credential (captcha services: 2captcha "key", 9kw "apikey",
# DeathByCaptcha "password"). Their values never go into the debug log - users post it.
_SECRET_FIELDS = ('key', 'apikey', 'api_key', 'password', 'passwd')
_SECRET_FIELD_RE = re.compile(r'(?<![A-Za-z0-9_])(%s)=[^&\s\'"]+' % '|'.join(_SECRET_FIELDS), re.IGNORECASE)


def maskSecrets(value):
    """`value` (URL, form body, dict of params or post data) for the debug log, credentials as ***."""
    if isinstance(value, dict):
        return {k: '***' if str(k).lower() in _SECRET_FIELDS else maskSecrets(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(maskSecrets(v) for v in value)
    if isinstance(value, basestring):  # py2: utf-8 str stays str (a unicode result would break printDBG)
        return _SECRET_FIELD_RE.sub(r'\1=***', value)
    if isinstance(value, bytes):
        return _SECRET_FIELD_RE.sub(r'\1=***', value.decode('utf-8', 'replace'))
    return value


# curl-impersonate (libs/curlimpersonate.py): hosts whose Cloudflare let a request with Chrome's
# TLS/HTTP2 fingerprint through (found by getPageCFProtection, or a host's own impersonate=True
# request that got an answer) - every later getPage() / saveWebFile() to them goes that way for the
# rest of the session (covers from IconMenager, subtitles, ... come without the host's params).
# Stored without a leading "www."; a registered name also covers its subdomains
# (mlblive.net -> www.mlblive.net, img.mlblive.net), never its parent or sibling domains.
_impersonateDomains = set()
_impersonateMissingLogged = [False]


def _impersonateDomain(url):
    try:
        host = (urlparse(url).hostname or '').lower()
    except Exception:
        return ''
    if host.startswith('www.') and host.count('.') >= 2:
        host = host[4:]
    return host


def _impersonateMatch(url):
    """the registered name that covers url's host (itself or a parent domain), else ''"""
    host = _impersonateDomain(url)
    while host and '.' in host:
        if host in _impersonateDomains:
            return host
        host = host.split('.', 1)[1]
    return ''


def _impersonateRegister(url):
    domain = _impersonateDomain(url)
    if domain and not _impersonateMatch(url):
        _impersonateDomains.add(domain)  # set.add: atomic in CPython, the worker threads share it
        printDBG('impersonate: %s registered for later requests (pages, covers, files)' % domain)


# AVIF images are ISO-BMFF files: a 4-byte box size, then "ftyp" + brand
FTYP_IMAGE_BRANDS = (b'ftypavif', b'ftypavis')


def ConvertibleImageFirstBytes():
    # first bytes of the image types convertWebp can turn into JPEG on this box (WebP: Pillow or ffmpeg,
    # AVIF: ffmpeg with an AV1 decoder) - nothing when there is no converter, the picture loader can't show them
    ret = []
    hasFFmpeg = IsExecutable('ffmpeg')
    if hasPIL or hasFFmpeg:
        ret.append(b'RI')
    if hasFFmpeg:
        ret.extend(FTYP_IMAGE_BRANDS)
    return ret


def MatchFirstBytes(data, prefixes):
    # first-bytes check of a download: a plain prefix, or an ftyp brand at offset 4
    data = ensure_binary(data)
    for item in prefixes:
        item = ensure_binary(item)
        if item in FTYP_IMAGE_BRANDS:
            if data[4:12] == item:
                return True
        elif data.startswith(item):
            return True
    return False


def IsConvertibleImage(file_path):
    # WebP / AVIF content, whatever the file name says - the Enigma2 picture loader shows neither
    try:
        with open(file_path, 'rb') as f:
            head = f.read(12)
    except Exception:
        return False
    return (head[:4] == b'RIFF' and head[8:12] == b'WEBP') or head[4:12] in FTYP_IMAGE_BRANDS


def _isGzipFile(file_path):
    try:
        with open(file_path, 'rb') as f:
            return f.read(2) == b'\x1f\x8b'
    except Exception:
        return False


def ImageFileNeedsPreparing(file_path):
    # a picture the Enigma2 picture loader can't show as it is: still gzip-encoded (some image CDNs compress
    # even unasked) or WebP/AVIF content, whatever the file name says
    return _isGzipFile(file_path) or IsConvertibleImage(file_path)


def PrepareImageFile(file_path, source_path=None):
    # in place: undo the gzip encoding, then WebP/AVIF -> JPEG like the list icons (IconMenager).
    # source_path: work on file_path as a copy of it - for the user's own pictures, which must stay untouched.
    # Run it in a worker thread: there convertWebp also waits for an ffmpeg conversion
    try:
        if source_path:
            shutil.copyfile(source_path, file_path)
        if _isGzipFile(file_path):
            with open(file_path, 'rb') as f:
                data = DecodeGzipped(f.read())
            with open(file_path, 'wb') as f:
                f.write(data)
        if IsConvertibleImage(file_path):
            common().convertWebp(file_path)
    except Exception:
        printExc()


def DescribeImageFile(path):
    # for the log when a picture can't be shown: size and the first bytes tell an html error page, an empty
    # file or an unconverted WebP/AVIF apart
    try:
        with open(path, 'rb') as f:
            head = f.read(16)
        return "file[%s] size[%d] head[%r]" % (path, os.path.getsize(path), head)
    except Exception as e:
        return "file[%s] not readable (%s)" % (path, e)


def DecodeGzipped(data):
    if isPY2():
        buf = StringIO(data)
        f = gzip.GzipFile(fileobj=buf)
        return f.read()
    else:
        #return gzip.decompress(data)
        buf = BytesIO(data)
        f = gzip.GzipFile(fileobj=buf)
        return f.read()


def EncodeGzipped(data):
    if isPY2():
        f = StringIO()
    else:
        f = BytesIO()
    gzf = gzip.GzipFile(mode="wb", fileobj=f, compresslevel=1)
    gzf.write(data)
    gzf.close()
    encoded = f.getvalue()
    f.close()
    return encoded


class _ImpersonateHeaders(dict):
    """py2: urllib2's HTTPMessage needs a file to parse - the response headers of a curl-impersonate
    request as a dict with case-insensitive get() / [] / in, plus getheader() like mimetools.Message"""

    def __init__(self, headers=None):
        dict.__init__(self)
        for name, value in (headers or {}).items():
            self[name] = value

    def __setitem__(self, name, value):
        dict.__setitem__(self, name.lower(), value)

    def __getitem__(self, name):
        return dict.__getitem__(self, name.lower())

    def __contains__(self, name):
        return dict.__contains__(self, name.lower())

    def get(self, name, default=None):
        return dict.get(self, name.lower(), default)

    getheader = get


class ImpersonateResponse(object):
    """what getPage(..., {'return_data': False}) returns for a curl-impersonate request: the urllib
    response methods over the body curl wrote to a temporary file, which close() removes"""

    def __init__(self, bodyFile, url, status, headers):
        self._path = bodyFile
        self._fp = open(bodyFile, 'rb')
        self.url = url
        self.code = self.status = status
        if isPY2():
            self.headers = _ImpersonateHeaders(headers)
        else:
            self.headers = HTTPMessage()
            for name, value in (headers or {}).items():
                self.headers[name] = value

    def geturl(self):
        return self.url

    def getcode(self):
        return self.code

    def info(self):
        return self.headers

    def read(self, size=-1):
        return self._fp.read(size)

    def readline(self, size=-1):
        return self._fp.readline(size)

    def close(self):
        if self._fp is not None:
            self._fp.close()
            self._fp = None
            try:
                os.remove(self._path)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class NoRedirection(urllib2_HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        infourl = urllib_addinfourl(fp, headers, req.get_full_url())
        if isPY2(): #status attribute is missing in p3 version of the addinfourl
            infourl.status = code
        infourl.code = code
        return infourl
    http_error_300 = http_error_302
    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302


class MultipartPostHandler(urllib2_BaseHandler):
    handler_order = urllib2_HTTPHandler.handler_order - 10

    def http_request(self, request):
        data = request.get_data()
        if data is not None and type(data) != str:
            content_type, data = self.encode_multipart_formdata(data)
            request.add_unredirected_header('Content-Type', content_type)
            request.add_data(data)
        return request

    def encode_multipart_formdata(self, fields):
        LIMIT = '-----------------------------14312495924498'
        CRLF = '\r\n'
        L = []
        for (key, value) in fields:
            L.append('--' + LIMIT)
            L.append('Content-Disposition: form-data; name="%s"' % key)
            L.append('')
            L.append(value)
        L.append('--' + LIMIT + '--')
        L.append('')
        body = CRLF.join(L)
        content_type = 'multipart/form-data; boundary=%s' % LIMIT
        return content_type, body

    https_request = http_request


class CParsingHelper:
    @staticmethod
    def listToDir(cList, idx):
        cTree = {'dat': ''}
        deep = 0
        while (idx + 1) < len(cList):
            if cList[idx].startswith('<ul') or cList[idx].startswith('<li'):
                deep += 1
                nTree, idx, nDeep = CParsingHelper.listToDir(cList, idx + 1)
                if 'list' not in cTree:
                    cTree['list'] = []
                cTree['list'].append(nTree)
                deep += nDeep
            elif cList[idx].startswith('</ul>') or cList[idx].startswith('</li>'):
                deep -= 1
                idx += 1
            else:
                cTree['dat'] += cList[idx]
                idx += 1
            if deep < 0:
                break
        return cTree, idx, deep

    @staticmethod
    def getSearchGroups(data, pattern, grupsNum=1, ignoreCase=False):
        return ph.search(data, pattern, ph.IGNORECASE if ignoreCase else 0, grupsNum)

    @staticmethod
    def getDataBeetwenReMarkers(data, pattern1, pattern2, withMarkers=True):
        match1 = pattern1.search(data)
        if None == match1 or -1 == match1.start(0):
            return False, ''
        match2 = pattern2.search(data[match1.end(0):])
        if None == match2 or -1 == match2.start(0):
            return False, ''

        if withMarkers:
            return True, data[match1.start(0): (match1.end(0) + match2.end(0))]
        else:
            return True, data[match1.end(0): (match1.end(0) + match2.start(0))]

    @staticmethod
    def getDataBeetwenMarkers(data, marker1, marker2, withMarkers=True, caseSensitive=True):
        flags = 0
        if withMarkers:
            flags |= ph.START_E | ph.END_E
        if not caseSensitive:
            flags |= ph.IGNORECASE
        return ph.find(data, marker1, marker2, flags)

    @staticmethod
    def getAllItemsBeetwenMarkers(data, marker1, marker2, withMarkers=True, caseSensitive=True):
        flags = 0
        if withMarkers:
            flags |= ph.START_E | ph.END_E
        if not caseSensitive:
            flags |= ph.IGNORECASE
        return ph.findall(data, marker1, marker2, flags)

    @staticmethod
    def rgetAllItemsBeetwenMarkers(data, marker1, marker2, withMarkers=True, caseSensitive=True):
        flags = 0
        if withMarkers:
            flags |= ph.START_E | ph.END_E
        if not caseSensitive:
            flags |= ph.IGNORECASE
        return ph.rfindall(data, marker1, marker2, flags)

    @staticmethod
    def rgetDataBeetwenMarkers2(data, marker1, marker2, withMarkers=True, caseSensitive=True):
        flags = 0
        if withMarkers:
            flags |= ph.START_E | ph.END_E
        if not caseSensitive:
            flags |= ph.IGNORECASE
        return ph.rfind(data, marker1, marker2, flags)

    @staticmethod
    def rgetDataBeetwenMarkers(data, marker1, marker2, withMarkers=True):
        # this methods is not working as expected, but is is used in many places
        # so I will leave at it is, please use rgetDataBeetwenMarkers2
        idx1 = data.rfind(marker1)
        if -1 == idx1:
            return False, ''
        idx2 = data.rfind(marker2, idx1 + len(marker1))
        if -1 == idx2:
            return False, ''
        if withMarkers:
            idx2 = idx2 + len(marker2)
        else:
            idx1 = idx1 + len(marker1)
        return True, data[idx1:idx2]

    @staticmethod
    def getDataBeetwenNodes(data, node1, node2, withNodes=True, caseSensitive=True):
        flags = 0
        if withNodes:
            flags |= ph.START_E | ph.END_E
        if not caseSensitive:
            flags |= ph.IGNORECASE
        return ph.find(data, node1, node2, flags)

    @staticmethod
    def getAllItemsBeetwenNodes(data, node1, node2, withNodes=True, numNodes=-1, caseSensitive=True):
        flags = 0
        if withNodes:
            flags |= ph.START_E | ph.END_E
        if not caseSensitive:
            flags |= ph.IGNORECASE
        return ph.findall(data, node1, node2, flags, limits=numNodes)

    @staticmethod
    def rgetDataBeetwenNodes(data, node1, node2, withNodes=True, caseSensitive=True):
        flags = 0
        if withNodes:
            flags |= ph.START_E | ph.END_E
        if not caseSensitive:
            flags |= ph.IGNORECASE
        return ph.rfind(data, node1, node2, flags)

    @staticmethod
    def rgetAllItemsBeetwenNodes(data, node1, node2, withNodes=True, numNodes=-1, caseSensitive=True):
        flags = 0
        if withNodes:
            flags |= ph.START_E | ph.END_E
        if not caseSensitive:
            flags |= ph.IGNORECASE
        return ph.rfindall(data, node1, node2, flags, limits=numNodes)

    # this method is useful only for developers
    # to dump page code to the file
    @staticmethod
    def writeToFile(file, data, mode="w"):
        #helper to see html returned by ajax
        file_path = file
        text_file = open(file_path, mode)
        text_file.write(data)
        text_file.close()

    @staticmethod
    def getNormalizeStr(txt, idx=None):
        POLISH_CHARACTERS = {u'ą': u'a', u'ć': u'c', u'ę': u'ę', u'ł': u'l', u'ń': u'n', u'ó': u'o', u'ś': u's', u'ż': u'z', u'ź': u'z',
                             u'Ą': u'A', u'Ć': u'C', u'Ę': u'E', u'Ł': u'L', u'Ń': u'N', u'Ó': u'O', u'Ś': u'S', u'Ż': u'Z', u'Ź': u'Z',
                             u'á': u'a', u'é': u'e', u'í': u'i', u'ñ': u'n', u'ó': u'o', u'ú': u'u', u'ü': u'u',
                             u'Á': u'A', u'É': u'E', u'Í': u'I', u'Ñ': u'N', u'Ó': u'O', u'Ú': u'U', u'Ü': u'U',
                            }
        if isPY2():
            txt = txt.decode('utf-8')
        else: #PY3
            if isinstance(txt, bytes):
                txt = txt.decode('utf-8')
        if None != idx:
            txt = txt[idx]
        nrmtxt = unicodedata.normalize('NFC', txt)
        ret_str = []
        for item in nrmtxt:
            if ord(item) > 128:
                item = POLISH_CHARACTERS.get(item)
                if item:
                    ret_str.append(item)
            else: # pure ASCII character
                ret_str.append(item)
        if isPY2():
            return ''.join(ret_str).encode('utf-8')
        else:
            return ''.join(ret_str)

    @staticmethod
    def isalpha(txt, idx=None):
        return CParsingHelper.getNormalizeStr(txt, idx).isalpha()

    @staticmethod
    def cleanHtmlStr(str):
        return ph.clean_html(str)


# browser versions for all User-Agents below - only change them here
CHROME_VERSION = '154'  # also Edge and Android Chrome
FIREFOX_VERSION = '157'
OPERA_VERSION = '136'
OPERA_CHROME_VERSION = '152'  # Opera ships an older Chromium than Chrome
SAFARI_VERSION = '27.0'  # also iOS / iPadOS
SAFARI_IOS_UA_VERSION = '18_7'  # since Safari 26 the iOS version in the UA is frozen
SAMSUNG_VERSION = '30.0'
SAMSUNG_CHROME_VERSION = '143'
VLC_VERSION = '3.0.24'

_CHROME = 'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0' % CHROME_VERSION
_FIREFOX = 'rv:%s.0) Gecko/20100101 Firefox/%s.0' % (FIREFOX_VERSION, FIREFOX_VERSION)
_SAFARI_IOS = 'OS %s like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Mobile/15E148 Safari/604.1' % (SAFARI_IOS_UA_VERSION, SAFARI_VERSION)
_MAG = 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) %s stbapp ver: 2 rev: 250 Safari/533.3'


class common:
    HOST = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) %s Safari/537.36' % _CHROME
    HEADER = None
    ph = CParsingHelper
    # every User-Agent can be asked for by its name, e.g. getDefaultHeader(browser='android')
    USER_AGENTS = {
        'chrome': HOST,
        'chrome_mac': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) %s Safari/537.36' % _CHROME,
        'chrome_linux': 'Mozilla/5.0 (X11; Linux x86_64) %s Safari/537.36' % _CHROME,
        'firefox': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; %s' % _FIREFOX,
        'firefox_mac': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; %s' % _FIREFOX,
        'firefox_linux': 'Mozilla/5.0 (X11; Linux x86_64; %s' % _FIREFOX,
        'edge': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) %s Safari/537.36 Edg/%s.0.0.0' % (_CHROME, CHROME_VERSION),
        'opera': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36 OPR/%s.0.0.0' % (OPERA_CHROME_VERSION, OPERA_VERSION),
        'safari': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15' % SAFARI_VERSION,
        'iphone': 'Mozilla/5.0 (iPhone; CPU iPhone %s' % _SAFARI_IOS,
        'ipad': 'Mozilla/5.0 (iPad; CPU %s' % _SAFARI_IOS,
        'android': 'Mozilla/5.0 (Linux; Android 10; K) %s Mobile Safari/537.36' % _CHROME,
        'samsung': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/%s Chrome/%s.0.0.0 Mobile Safari/537.36' % (SAMSUNG_VERSION, SAMSUNG_CHROME_VERSION),
        # media player, for IPTV/m3u servers and CDNs that only let players through
        'vlc': 'VLC/%s LibVLC/%s' % (VLC_VERSION, VLC_VERSION),
        # MAG set-top boxes (Stalker portals)
        'mag200': _MAG % 'MAG200',
        'mag250': _MAG % 'MAG250',
        'mag254': _MAG % 'MAG254',
        'mag322': _MAG % 'MAG322',
        'mag352': _MAG % 'MAG352',
        'mag540': _MAG % 'MAG540',
    }
    # randomUA=True picks from the group; without it a group name gives its first entry
    USER_AGENT_GROUPS = {
        'chrome': ['chrome', 'chrome_mac', 'chrome_linux'],
        'firefox': ['firefox', 'firefox_mac', 'firefox_linux'],
        'desktop': ['chrome', 'chrome_mac', 'chrome_linux', 'firefox', 'firefox_mac', 'firefox_linux', 'edge', 'opera', 'safari'],
        'mobile': ['iphone', 'android', 'samsung', 'ipad'],
        'mag': ['mag250', 'mag200', 'mag254', 'mag322', 'mag352', 'mag540'],
    }
    USER_AGENT_ALIASES = {'iphone_3_0': 'iphone', 'qt': 'mag'}

    @staticmethod
    def getDefaultUserAgent(browser='chrome', randomUA=False):
        # unknown names (also 'Firefox' with a capital F) keep getting the Chrome UA like before;
        # randomUA picks a new UA on every call, so call it once per host and reuse the header -
        # Cloudflare's cf_clearance and many session cookies only stay valid for the same UA
        browser = common.USER_AGENT_ALIASES.get(browser, browser)
        group = common.USER_AGENT_GROUPS.get(browser)
        if randomUA and group:
            browser = random.choice(group)
        elif group and browser not in common.USER_AGENTS:
            browser = group[0]
        return common.USER_AGENTS.get(browser, common.HOST)

    @staticmethod
    def getDefaultHeader(browser='firefox', randomUA=False):
        ua = common.getDefaultUserAgent(browser, randomUA)
        HTTP_HEADER = {'User-Agent': ua, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Encoding': 'gzip, deflate', 'DNT': 1}
        return dict(HTTP_HEADER)

    @staticmethod
    def getParamsFromUrlWithMeta(url, baseHeaderOutParams=None):
        from Plugins.Extensions.IPTVPlayer.iptvdm.iptvdh import DMHelper
        HANDLED_HTTP_HEADER_PARAMS = DMHelper.HANDLED_HTTP_HEADER_PARAMS #['Host', 'User-Agent', 'Referer', 'Cookie', 'Accept',  'Range']
        outParams = {}
        tmpParams = {}
        postData = None
        if isinstance(url, strwithmeta):
            if None != baseHeaderOutParams:
                tmpParams['header'] = baseHeaderOutParams
            else:
                tmpParams['header'] = {}
            for key in url.meta:
                if key in HANDLED_HTTP_HEADER_PARAMS:
                    tmpParams['header'][key] = url.meta[key]
            if 0 < len(tmpParams['header']):
                outParams = tmpParams
            if 'iptv_proxy_gateway' in url.meta:
                outParams['proxy_gateway'] = url.meta['iptv_proxy_gateway']
            if 'iptv_http_proxy' in url.meta:
                outParams['http_proxy'] = url.meta['iptv_http_proxy']
        return outParams, postData

    @staticmethod
    def getBaseUrl(url, domainOnly=False):
        parsed_uri = urlparse(url)
        if domainOnly:
            domain = '{uri.netloc}'.format(uri=parsed_uri)
        else:
            domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        return domain

    @staticmethod
    def getFullUrl(url, mainUrl='https://fake/'):
        if not url:
            return ''
        if url.startswith('./'):
            url = url[1:]

        currUrl = mainUrl
        mainUrl = common.getBaseUrl(currUrl)

        if url.startswith('//'):
            proto = mainUrl.split('://', 1)[0]
            url = proto + ':' + url
        elif url.startswith('://'):
            proto = mainUrl.split('://', 1)[0]
            url = proto + url
        elif url.startswith('/'):
            url = mainUrl + url[1:]
        elif 0 < len(url) and '://' not in url:
            if currUrl == mainUrl:
                url = mainUrl + url
            else:
                url = urljoin(currUrl, url)
        return url

    @staticmethod
    def isValidUrl(url):
        return url.startswith('http://') or url.startswith('https://')

    @staticmethod
    def buildHTTPQuery(query):
        def _process(query, data, key_prefix):
            if isinstance(data, dict):
                for key, value in iterDictItems(data):
                    key = '%s[%s]' % (key_prefix, key) if key_prefix else key
                    _process(query, value, key)
            elif isinstance(data, list):
                for idx in range(len(data)):
                    _process(query, data[idx], '%s[%s]' % (key_prefix, idx))
            else:
                query.append((key_prefix, data))
        _query = []
        _process(_query, query, '')
        return _query

    @staticmethod
    def buildURLWithParams(url='http://fake/', Query=None, MultiQuery=None):  # NOSONAR
        # adds or replaces query parameters; the other parameters stay byte for byte (repeated keys, empty
        # values, their own encoding), as does the #fragment; a list value gives a repeated key
        if not Query:
            return url
        try:
            if MultiQuery:
                newParams = common.buildHTTPQuery(Query)
            else:
                newParams = list(Query.items()) if isinstance(Query, dict) else list(Query)
            newKeys = set(str(param[0]) for param in newParams)
            parsedUrl = urlparse(url)
            query = [part for part in parsedUrl.query.split('&') if part and urllib_unquote_plus(part.split('=', 1)[0]) not in newKeys]
            newQuery = urllib_urlencode(newParams, doseq=True)
            if newQuery:
                query.append(newQuery)
            return urlunparse(parsedUrl._replace(query='&'.join(query)))
        except Exception:
            printExc()
            return url

    def __init__(self, proxyURL='', useProxy=False, useMozillaCookieJar=True):
        self.proxyURL = proxyURL
        self.useProxy = useProxy
        self.geolocation = {}
        self.meta = {} # metadata from previus request

        self.curlSession = None
        self.pyCurlAvailable = None
        if not useMozillaCookieJar:
            raise Exception("You should stop use parameter useMozillaCookieJar it change nothing, because from only MozillaCookieJar can be used")

    def reportHttpsError(self, type, url, msg):
        domain = self.getBaseUrl(url, True)
        messages = []
        messages.append(_('HTTPS connection error "%s"\n') % msg)
        messages.append(_('It looks like your current configuration do not allow to connect to the https://%s/.\n') % domain)

        if type == 'verify' and IsHttpsCertValidationEnabled():
            messages.append(_('You can disable HTTPS certificates validation in the E2iPlayer configuration to suppress this problem.'))
        else:
            pyCurlInstalled = False
            try:
                verInfo = pycurl.version_info()
                printDBG("usePyCurl VERSION: %s" % [verInfo])
                if verInfo[4] & (1 << 7) and verInfo[1].startswith('7.6') and verInfo[5] == 'wolfSSL/3.15.3':
                    pyCurlInstalled = True
            except Exception:
                printExc()
            if pyCurlInstalled:
                if not UsePyCurl():
                    messages.append(_('You can enable PyCurl in the E2iPlayer configuration to fix this problem.'))
                else:
                    messages.append(_('Please report this problem to the developer %s.') % 'iptvplayere2@gmail.com')
            else:
                messages.append(_('You can install PyCurl package from %s to fix this problem.') % 'http://www.iptvplayer.gitlab.io/')
        GetIPTVNotify().push('\n'.join(messages), 'error', 40, type + domain, 40)

    def usePyCurl(self):
        bRet = False
        if UsePyCurl():
            if self.pyCurlAvailable == None:
                try:
                    #import pycurl as pycurl
                    #test = pycurl.SSLVERSION_TLSv1_3
                    verInfo = pycurl.version_info()
                    printDBG("usePyCurl VERSION: %s" % [verInfo])
                    # #define CURL_VERSION_ASYNCHDNS    (1<<7)
                    # we need to have ASYNC DNS to be able "cancel"
                    # request
                    if verInfo[4] & (1 << 7):
                        self.pyCurlAvailable = True
                    else:
                        self.pyCurlAvailable = False
                except Exception:
                    self.pyCurlAvailable = False
                    printExc()
            bRet = self.pyCurlAvailable
        return bRet

    def getCountryCode(self, lower=True):
        if 'countryCode' not in self.geolocation:
            sts, data = self.getPage('http://ip-api.com/json')
            if sts:
                try:
                    self.geolocation['countryCode'] = json_loads(data)['countryCode']
                except Exception:
                    printExc()
        return self.geolocation.get('countryCode', '').lower()

    def _pyCurlLoadCookie(self, cookiefile, ignoreDiscard=True, ignoreExpires=False):
        cj = cookielib.MozillaCookieJar()
        f = open(cookiefile)
        lines = f.readlines()
        f.close()
        for idx in range(len(lines)):
            lineNeedFix = False
            fields = lines[idx].split('\t')
            if len(fields) < 5:
                continue
            if fields[0].startswith('#HttpOnly_'):
                fields[0] = fields[0][10:]
                lineNeedFix = True
            if fields[4] == '0':
                fields[4] = ''
                lineNeedFix = True
            if lineNeedFix:
                lines[idx] = '\t'.join(fields)
        if isPY2():
            cj._really_load(StringIO(''.join(lines)), cookiefile, ignore_discard=ignoreDiscard, ignore_expires=ignoreExpires)
        else:
            cj._really_load(StringIO(''.join(lines)), cookiefile, ignore_discard=ignoreDiscard, ignore_expires=ignoreExpires)
        return cj

    def clearCookie(self, cookiefile, leaveNames=[], removeNames=None, ignoreDiscard=True, ignoreExpires=False):
        if not os.path.isfile(cookiefile):
            # nothing saved yet for this host - nothing to clear (was logged as an exception)
            return True
        try:
            toRemove = []
            if self.usePyCurl():
                cj = self._pyCurlLoadCookie(cookiefile, ignoreDiscard, ignoreExpires)
            else:
                cj = cookielib.MozillaCookieJar()
            cj.load(cookiefile, ignore_discard=ignoreDiscard)
            for cookie in cj:
                if cookie.name not in leaveNames and (None == removeNames or cookie.name in removeNames):
                    toRemove.append(cookie)
            for cookie in toRemove:
                cj.clear(cookie.domain, cookie.path, cookie.name)
            cj.save(cookiefile, ignore_discard=ignoreDiscard)
        except Exception:
            printExc()
            return False
        return True

    def getCookieItem(self, cookiefile, item):
        cookiesDict = self.getCookieItems(cookiefile)
        return cookiesDict.get(item, '')

    def getCookie(self, cookiefile, ignoreDiscard=True, ignoreExpires=False):
        cj = None
        try:
            if self.usePyCurl():
                cj = self._pyCurlLoadCookie(cookiefile, ignoreDiscard, ignoreExpires)
            else:
                cj = cookielib.MozillaCookieJar()
                cj.load(cookiefile, ignore_discard=ignoreDiscard)
        except Exception:
            printExc()
        return cj

    def getCookieItems(self, cookiefile, ignoreDiscard=True, ignoreExpires=False):
        cookiesDict = {}
        if not cookiefile or not os.path.isfile(cookiefile):
            # nothing saved yet for this host - no cookies (was logged as two exceptions)
            return cookiesDict
        try:
            cj = self.getCookie(cookiefile, ignoreDiscard, ignoreExpires)
            for cookie in cj or []:
                cookiesDict[cookie.name] = cookie.value
        except Exception:
            printExc()
        return cookiesDict

    def getCookieHeader(self, cookiefile, allowedNames=[], unquote=True, ignoreDiscard=True, ignoreExpires=False):
        ret = ''
        try:
            cookiesDict = self.getCookieItems(cookiefile, ignoreDiscard, ignoreExpires)
            for name in cookiesDict:
                if 0 < len(allowedNames) and name not in allowedNames:
                    continue
                value = cookiesDict[name]
                if unquote:
                    value = urllib_unquote(value)
                ret += '%s=%s; ' % (name, value)
        except Exception:
            printExc()
        return ret

    def _getPageWithPyCurl(self, url, params={}, post_data=None):
        if IsMainThread():
            msg1 = _('It is not allowed to call getURLRequestData from main thread.')
            msg2 = _('You should never perform block I/O operations in the __init__.')
            GetIPTVNotify().push(' '.join([msg1, msg2]), 'error', 40)
            raise Exception("Wrong usage!")

        # by default we will work in return_data mode
        if 'return_data' not in params:
            params['return_data'] = True

        if 'save_to_file' in params: # some cleaning
            params['save_to_file'] = params['save_to_file'].replace('//', '/')

        self.meta = {}
        metadata = self.meta
        out_data = None
        sts = False

        if isPY2():
            CurrBuffer = StringIO()
        else:
            CurrBuffer = BytesIO()
        checkFromFirstBytes = params.get('check_first_bytes', [])
        fileHandler = None
        firstAttempt = [True]
        maxDataSize = params.get('max_data_size', -1)

        responseHeaders = {}

        def _headerFunction(headerLine):
            headerLine = ensure_str(headerLine)
            if ':' not in headerLine:
                if 0 == maxDataSize:
                    if headerLine in ['\r\n', '\n']:
                        if 'n' not in responseHeaders:
                            return 0
                        responseHeaders.pop('n', None)
                    elif headerLine.startswith('HTTP/') and headerLine.split(' 30', 1)[-1][0:1] in ['1', '2', '3', '7']: # new location with 301, 302, 303, 307
                        responseHeaders['n'] = True
                return

            name, value = headerLine.split(':', 1)

            name = name.strip()
            value = value.strip()

            name = name.lower()
            responseHeaders[name] = value

        def _breakConnection(toWriteData):
            CurrBuffer.write(toWriteData)
            if maxDataSize <= CurrBuffer.tell():
                return 0

        def _bodyFunction(toWriteData):
            # we started receiving body data so all headers are available
            # so we can check them if needed
            if firstAttempt[0]:
                firstAttempt[0] = False
                if 'check_maintype' in params and \
                    params['check_maintype'] != responseHeaders.get('content-type', '').split('/', 1)[0]:
                    printDBG('wrong maintype: %s' % responseHeaders.get('content-type', ''))
                    metadata['abort_reason'] = 'wrong content-type %s' % responseHeaders.get('content-type', '')
                    return 0

                if 'check_subtypes' in params:
                    contentSubType = responseHeaders.get('content-type', '').split('/', 1)[-1]
                    try:
                        valid = False
                        for subType in params['check_subtypes']:
                            if subType == contentSubType:
                                valid = True
                                break
                        if not valid:
                            printDBG('wrong type: %s' % responseHeaders.get('content-type', ''))
                            metadata['abort_reason'] = 'wrong content-type %s' % responseHeaders.get('content-type', '')
                            return 0
                    except Exception:
                        printExc()
                        return 0 # wrong params?

            # if we should check start body data
            if len(checkFromFirstBytes):
                CurrBuffer.write(toWriteData)
                toWriteData = None
                valid = False
                value = ensure_binary(CurrBuffer.getvalue())
                for toCheck in checkFromFirstBytes:
                    toCheck = ensure_binary(toCheck)
                    if toCheck in FTYP_IMAGE_BRANDS:
                        if len(value) < 12:
                            # it could be valid - we need to wait for more data
                            valid = True
                        elif value[4:12] == toCheck:
                            valid = True
                            del checkFromFirstBytes[:]
                            break
                    elif len(toCheck) <= len(value):
                        if value.startswith(toCheck):
                            valid = True
                            # valid no need to check anymore
                            del checkFromFirstBytes[:]
                            break
                    elif toCheck.startswith(value):
                        # it could be valid - we need to wait for more data
                        valid = True
                if not valid:
                    printDBG('wrong body: %s' % hexlify(value))
                    metadata['abort_reason'] = 'not a picture, content-type[%s] first bytes %r' % (
                        responseHeaders.get('content-type', ''), value[:16])
                    return 0

            if fileHandler != None and 0 == len(checkFromFirstBytes):
                # all check were done so, we can start write data to file
                try:
                    if fileHandler.tell() == 0 and CurrBuffer.tell() > 0:
                        fileHandler.write(ensure_binary(CurrBuffer.getvalue()))

                    if toWriteData != None:
                        fileHandler.write(toWriteData)
                except Exception:
                    printExc()
                    return 0 # wrong file handle

            if toWriteData != None and params['return_data']:
                CurrBuffer.write(toWriteData)

        def _terminateFunction(download_t, download_d, upload_t, upload_d):
            if IsThreadTerminated():
                printDBG(">> _terminateFunction")
                return True # anything else then None will cause pycurl perform cancel

        try:
            timeout = params.get('timeout', None)

            if 'host' in params:
                host = params['host']
            else:
                host = self.HOST

            if 'header' in params:
                headers = params['header']
            elif None != self.HEADER:
                headers = self.HEADER
            else:
                headers = {'User-Agent': host}

            if 'User-Agent' not in headers:
                headers['User-Agent'] = host

            printDBG('pCommon - getPageWithPyCurl() -> params: ' + str(params))
            printDBG('pCommon - getPageWithPyCurl() -> headers: ' + str(headers))

            if 'save_to_file' in params:
                fileHandler = file(params['save_to_file'], "wb")

            # we can not kill thread when we are in any function of pycurl
            SetThreadKillable(False)

            if None == self.curlSession:
                curlSession = pycurl.Curl()
            elif params.get('use_new_session', False):
                curlSession = self.curlSession
                self.curlSession = None
                curlSession.close()
                curlSession = pycurl.Curl()
            else:
                # use previous session to be able to reuse connection
                curlSession = self.curlSession
                self.curlSession = None
                curlSession.reset()

            if params.get('use_fresh_connect', False):
                curlSession.setopt(pycurl.FRESH_CONNECT, 1)

            customHeaders = []
            for key in headers:
                lKey = key.lower()
                if lKey == 'user-agent':
                    curlSession.setopt(pycurl.USERAGENT, headers[key])
                elif lKey == 'cookie':
                    curlSession.setopt(pycurl.COOKIE, headers[key])
                elif lKey == 'referer':
                    curlSession.setopt(pycurl.REFERER, headers[key])
                else:
                    customHeaders.append('%s: %s' % (key, headers[key]))
            if len(customHeaders):
                curlSession.setopt(pycurl.HTTPHEADER, customHeaders)

            curlSession.setopt(pycurl.ACCEPT_ENCODING, "") # enable all supported built-in compressions
            # ipv4_only: sites whose Cloudflare blocks IPv6 clients (curl resolves names itself, a socket-level
            # IPv4 lookup does not reach it); ipv6_only: a token bound to the client address must be fetched
            # over the family the player will use (fails without IPv6 - the caller falls back). ipv4_only wins
            # when both are set; set every time, a session can be reused. Only pycurl and curl-impersonate
            # honour them, the urllib path has no address family control.
            if params.get('ipv4_only'):
                ipResolve = pycurl.IPRESOLVE_V4
            elif params.get('ipv6_only'):
                ipResolve = pycurl.IPRESOLVE_V6
            else:
                ipResolve = pycurl.IPRESOLVE_WHATEVER
            curlSession.setopt(pycurl.IPRESOLVE, ipResolve)
            if None != params.get('ssl_protocol', None):
                sslProtoVer = self.getPyCurlSSLProtocolVersion(params['ssl_protocol'])
                if None != sslProtoVer:
                    curlSession.setopt(pycurl.SSLVERSION, sslProtoVer)

            if 'use_cookie' not in params and 'cookiefile' in params and ('load_cookie' in params or 'save_cookie' in params):
                params['use_cookie'] = True

            if params.get('use_cookie', False):
                cookiesStr = ''
                for cookieKey in list(params.get('cookie_items', {}).keys()):
                    printDBG("cookie_item[%s=%s]" % (cookieKey, params['cookie_items'][cookieKey]))
                    cookiesStr += '%s=%s; ' % (cookieKey, params['cookie_items'][cookieKey])

                if cookiesStr != '':
                    curlSession.setopt(pycurl.COOKIE, cookiesStr) #'Set-Cookie: foo=baar') #

                if params.get('load_cookie', False):
                    curlSession.setopt(pycurl.COOKIEFILE, params.get('cookiefile', ''))

                if params.get('save_cookie', False):
                    curlSession.setopt(pycurl.COOKIEJAR, params.get('cookiefile', ''))

            if timeout != None:
                curlSession.setopt(pycurl.CONNECTTIMEOUT, timeout) # in seconds - connection timeout
                curlSession.setopt(pycurl.LOW_SPEED_TIME, timeout) # in seconds
                curlSession.setopt(pycurl.LOW_SPEED_LIMIT, 10) # in bytes
                # set maximum time the request is allowed to take
                #curlSession.setopt(pycurl.TIMEOUT, 300) # in seconds

            if not params.get('no_redirection', False):
                curlSession.setopt(pycurl.FOLLOWLOCATION, 1)
                curlSession.setopt(pycurl.UNRESTRICTED_AUTH, 1)
                curlSession.setopt(pycurl.MAXREDIRS, 5)

            # debug
            #curlSession.setopt(pycurl.VERBOSE, 1)
            #curlSession.setopt(pycurl.DEBUGFUNCTION, debug_fun)

            if not IsHttpsCertValidationEnabled():
                curlSession.setopt(pycurl.SSL_VERIFYHOST, 0)
                curlSession.setopt(pycurl.SSL_VERIFYPEER, 0)
                #curlSession.setopt(pycurl.PROXY_SSL_VERIFYHOST, 0)
                curlSession.setopt(pycurl.PROXY_SSL_VERIFYPEER, 0)
            else:
                curlSession.setopt(pycurl.CAINFO, "/etc/ssl/certs/ca-certificates.crt")
                curlSession.setopt(pycurl.PROXY_CAINFO, "/etc/ssl/certs/ca-certificates.crt")

            #proxy support
            if self.useProxy:
                http_proxy = self.proxyURL
            else:
                http_proxy = ''
            #proxy from parameters (if available) overwrite default one
            if 'http_proxy' in params:
                http_proxy = params['http_proxy']
            if '' != http_proxy:
                printDBG('getPageWithPyCurl USE PROXY')
                curlSession.setopt(pycurl.PROXY, http_proxy)

            pageUrl = url
            proxy_gateway = params.get('proxy_gateway', '')
            if proxy_gateway != '':
                pageUrl = proxy_gateway.format(urllib_quote_plus(pageUrl, ''))
            printDBG("pageUrl: [%s]" % pageUrl)

            curlSession.setopt(pycurl.URL, pageUrl)

            if None != post_data:
                printDBG('pCommon - getPageWithPyCurl() -> post data: ' + str(post_data))
                if params.get('raw_post_data', False):
                    curlSession.setopt(pycurl.POSTFIELDS, post_data)
                elif params.get('multipart_post_data', False):
                    printDBG("multipart_post_data NOT SUPPORTED")
                    dataPost = post_data
                    curlSession.setopt(pycurl.HTTPPOST, post_data)
                    #curlSession.setopt(pycurl.CUSTOMREQUEST, "PUT")
                else:
                    curlSession.setopt(pycurl.POSTFIELDS, urllib_urlencode(post_data))

            curlSession.setopt(pycurl.HEADERFUNCTION, _headerFunction)

            if fileHandler:
                printDBG('pCommon - getPageWithPyCurl() -> fileHandler exists, pycurl.WRITEFUNCTION = _bodyFunction')
                curlSession.setopt(pycurl.WRITEFUNCTION, _bodyFunction)
            elif maxDataSize >= 0:
                printDBG('pCommon - getPageWithPyCurl() -> fileHandler exists, pycurl.WRITEFUNCTION = _breakConnection')
                curlSession.setopt(pycurl.WRITEFUNCTION, _breakConnection)
            else:
                printDBG('pCommon - getPageWithPyCurl() -> pycurl.WRITEDATA to CurrBuffer')
                curlSession.setopt(pycurl.WRITEDATA, CurrBuffer)

            curlSession.setopt(pycurl.NOPROGRESS, False)
            curlSession.setopt(pycurl.PROGRESSFUNCTION, _terminateFunction)
            curlSession.setopt(pycurl.NOSIGNAL, 1)
            #if 0 == maxDataSize:
            #    curlSession.setopt(pycurl.NOBODY, True);

            if not IsThreadTerminated():
                if maxDataSize >= 0:
                    try:
                        curlSession.perform()
                    except pycurl.error as e:
                        if e[0] != pycurl.E_WRITE_ERROR:
                            raise e
                        else:
                            printExc()
                else:
                    curlSession.perform()

                metadata['url'] = curlSession.getinfo(pycurl.EFFECTIVE_URL)
                metadata['status_code'] = curlSession.getinfo(pycurl.HTTP_CODE)
                metadata['size_download'] = curlSession.getinfo(pycurl.SIZE_DOWNLOAD)

                # reset will cause lost all cookies, so we force to saved them in the file
                if params.get('use_cookie', False) and params.get('save_cookie', False):
                    curlSession.setopt(pycurl.COOKIELIST, 'FLUSH')
                    curlSession.setopt(pycurl.COOKIELIST, 'ALL')

                curlSession.reset()
                # to be re-used in next request
                self.curlSession = curlSession

                # we should not use pycurl anymore
                SetThreadKillable(True)

                self.fillHeaderItems(metadata, responseHeaders, collectAllHeaders=params.get('collect_all_headers'))

                if params['return_data']:
                    out_data = ensure_str(CurrBuffer.getvalue())
                else:
                    out_data = ""

                out_data, metadata = self.handleCharset(params, out_data, metadata)
                if metadata['status_code'] != 200:
                    ignoreCodeRanges = params.get('ignore_http_code_ranges', [(404, 404), (500, 500)])
                    for ignoreCodeRange in ignoreCodeRanges:
                        if metadata['status_code'] >= ignoreCodeRange[0] and metadata['status_code'] <= ignoreCodeRange[1]:
                            sts = True
                            break
                else:
                    sts = True

            if fileHandler:
                fileHandler.close()

            if metadata.get('status_code') == 200 and 'check_first_bytes' in params and IsConvertibleImage(params['save_to_file']):
                # an image download (icons) that got WebP/AVIF
                self.convertWebp(params['save_to_file'])
        except pycurl.error as e:
            try:
                metadata['pycurl_error'] = (e[0], str(e[1]))
            except Exception:
                metadata['pycurl_error'] = (e.args[0], e.args[1]) # it seems pycurl in p3 has different structure
            if metadata['pycurl_error'][0] == getattr(pycurl, 'E_ABORTED_BY_CALLBACK', 42) and IsThreadTerminated():
                # the user left the list/host while loading: _terminateFunction aborts the transfer on purpose
                printDBG('pCommon - getPageWithPyCurl() -> request cancelled (thread terminated)')
            else:
                printExc()
        except Exception:
            printExc()

        SetThreadKillable(True)

        printDBG('pCommon - getPageWithPyCurl() return -> \nsts: %s\nmetadata: %s\n' % (sts, metadata))
        if params.get('with_metadata', False):
            out_data = strwithmeta(out_data, metadata)

        return sts, out_data

    def getPageWithPyCurl(self, url, params={}, post_data=None):
        # some error can be caused because of session reuse
        # if we use old curlSession and fail we should
        # re-try with fresh curlSession
        if self.curlSession != None:
            sessionReused = True
        else:
            sessionReused = False

        sts, data = False, None
        try:
            maxTries = 3
            tries = 0
            while tries < maxTries:
                tries += 1
                sts, data = self._getPageWithPyCurl(url, params, post_data)
                if not sts and 'pycurl_error' in self.meta and \
                   pycurl.E_SSL_CONNECT_ERROR == self.meta['pycurl_error'][0]:
                    if 'SSL_set_session failed' in self.meta['pycurl_error'][1] or '-308' in self.meta['pycurl_error'][1]:
                        printDBG("pCommon - getPageWithPyCurl() - retry with fresh session")
                        if sessionReused:
                            sessionReused = False
                            continue
                    elif '-313' in self.meta['pycurl_error'][1] and 'ssl_protocol' not in params:
                        params = dict(params)
                        params['ssl_protocol'] = 'TLSv1_2'
                        continue
                break

            if not sts and 'pycurl_error' in self.meta:
                if self.meta['pycurl_error'][0] == pycurl.E_SSL_CONNECT_ERROR:
                    self.reportHttpsError('other', url, self.meta['pycurl_error'][1])
                elif self.meta['pycurl_error'][0] in [pycurl.E_SSL_CACERT, pycurl.E_SSL_ISSUER_ERROR,
                                                      pycurl.E_SSL_PEER_CERTIFICATE, pycurl.E_SSL_CACERT_BADFILE]:
                    self.reportHttpsError('verify', url, self.meta['pycurl_error'][1])
                elif self.meta['pycurl_error'][0] == pycurl.E_SSL_INVALIDCERTSTATUS:
                    self.reportHttpsError('verify', url, self.meta['pycurl_error'][1])
        except Exception:
            printExc()
        return sts, data

    def fillHeaderItems(self, metadata, responseHeaders, camelCase=False, collectAllHeaders=False):
        returnKeys = ['content-type', 'content-disposition', 'content-length', 'location', 'last-modified']
        if camelCase:
            sourceKeys = ['Content-Type', 'Content-Disposition', 'Content-Length', 'Location', 'Last-Modified']
        else:
            sourceKeys = returnKeys
        for idx in range(len(returnKeys)):
            if sourceKeys[idx] in responseHeaders:
                metadata[returnKeys[idx]] = responseHeaders[sourceKeys[idx]]

        if collectAllHeaders:
            if "Access-Control-Allow-Headers" in responseHeaders:
                acah = responseHeaders["Access-Control-Allow-Headers"]
                acah_keys = acah.split(',')

                for key in acah_keys:
                    key = key.strip()
                    if key in responseHeaders:
                        metadata[key.lower()] = responseHeaders[key]

            # (py2: an HTTPMessage of urllib2 has items() but no iteritems() - iterDictItems failed on every
            # 403 answer, so its headers never reached the bot protection check)
            for header, value in responseHeaders.items():
                metadata[header.lower()] = value

    def _readHttpResponse(self, fp, maxSize=-1):
        # Some servers close the connection before delivering the full
        # response promised by Content-Length. httplib/http.client then
        # raises IncompleteRead and the partial body would otherwise be
        # lost entirely - use what was actually received instead. Doing
        # it once here, at the only place that actually calls read(),
        # covers every caller of getPage()/getURLRequestData() without
        # touching process-wide state (e.g. a global
        # httplib.HTTPResponse.read monkeypatch).
        try:
            if maxSize == -1:
                return fp.read()
            return fp.read(maxSize)
        except IncompleteRead as e:
            printDBG("common._readHttpResponse: IncompleteRead, using partial data (%d bytes)" % len(e.partial or b''))
            return e.partial

    def _useImpersonate(self, url, params):
        wanted = params.get('impersonate', None)
        if wanted is None:
            return _impersonateMatch(url) != ''
        return bool(wanted)

    def _impersonateFetch(self, url, params, post_data=None, outFile='', caller='getPageImpersonate'):
        '''one request through curl-impersonate with pCommon's params (header, cookies, post data, proxy,
        timeout, ...). Returns the curlimpersonate.fetch() dict for an answer (self.meta then has url,
        status_code, impersonate and the headers), None when the binary is missing or cannot run (the
        caller then uses the normal path), False when the request failed (main thread, no answer).
        outFile: curl writes the body there - the caller removes it when the answer is not wanted.
        An explicit params['impersonate'] that gets a 2xx/3xx registers the domain for later requests.'''
        binary = curlimpersonate.getImpersonateBinary()
        if not binary:
            if not _impersonateMissingLogged[0]:
                _impersonateMissingLogged[0] = True
                printDBG('pCommon - %s() curl-impersonate is not installed, using the normal HTTP path' % caller)
            return None

        self.meta = {}
        if IsMainThread():
            msg1 = _('It is not allowed to call getURLRequestData from main thread.')
            msg2 = _('You should never perform block I/O operations in the __init__.')
            GetIPTVNotify().push(' '.join([msg1, msg2]), 'error', 40)
            return False

        if 'header' in params:
            headers = params['header']
        elif None is not self.HEADER:
            headers = self.HEADER
        else:
            headers = {}

        useCookie = params.get('use_cookie', False)
        if 'use_cookie' not in params and 'cookiefile' in params and ('load_cookie' in params or 'save_cookie' in params):
            useCookie = True
        cookieFile = params.get('cookiefile', '') if useCookie else ''

        postBody = None
        if None is not post_data:
            printDBG('pCommon - %s() -> post data: %s' % (caller, maskSecrets(post_data)))
            if params.get('raw_post_data', False):
                postBody = ensure_binary(post_data)
            else:
                postBody = ensure_binary(urllib_urlencode(post_data))

        http_proxy = self.proxyURL if self.useProxy else ''
        if 'http_proxy' in params:
            http_proxy = params['http_proxy']

        pageUrl = url
        proxy_gateway = params.get('proxy_gateway', '')
        if proxy_gateway != '':
            pageUrl = proxy_gateway.format(urllib_quote_plus(pageUrl, ''))
        if '","' in pageUrl:  # see getURLRequestData
            pageUrl = pageUrl.split('"', 1)[0]
        pageUrl = self.iriToUri(pageUrl)

        printDBG('pCommon - %s() -> params: %s' % (caller, maskSecrets(params)))
        printDBG('pCommon - %s() -> headers: %s' % (caller, headers))
        printDBG("pageUrl: [%s]" % maskSecrets(pageUrl))

        metadata = self.meta
        try:
            res = curlimpersonate.fetch(binary, pageUrl, GetTmpDir(), headers=headers, cookieFile=cookieFile,
                                        loadCookie=params.get('load_cookie', False), saveCookie=params.get('save_cookie', False),
                                        cookieItems=params.get('cookie_items') if useCookie else None, postBody=postBody,
                                        noRedirection=params.get('no_redirection', False), timeout=params.get('timeout', None),
                                        proxy=http_proxy, insecure=not IsHttpsCertValidationEnabled(), ipv4Only=params.get('ipv4_only', False),
                                        maxDataSize=params.get('max_data_size', -1), shouldAbort=IsThreadTerminated,
                                        log=lambda msg: printDBG(maskSecrets(ensure_str(msg))), outFile=outFile,
                                        ipv6Only=params.get('ipv6_only', False))
        except curlimpersonate.ImpersonateUnavailable as e:
            printDBG('pCommon - %s() %s - using the normal HTTP path from now on' % (caller, e))
            curlimpersonate.markBinaryUnusable()
            return None
        except Exception:
            printExc()
            return False

        if isPY2():
            # curlimpersonate reads url, headers and curl's message as unicode - the hosts work with utf-8 str
            res['url'] = ensure_str(res['url'])
            res['error'] = ensure_str(res['error'])
            res['headers'] = dict((ensure_str(k), ensure_str(v)) for k, v in res['headers'].items())

        status = res['status']
        if res['aborted'] or res['exitcode'] != 0 or not status:
            metadata['curl_error'] = (res['exitcode'], res['error'])
            printDBG('pCommon - %s() failed: curl exit %s [%s] HTTP %s' % (caller, res['exitcode'], res['error'], status))
            return False

        metadata['url'] = res['url']
        metadata['status_code'] = status
        metadata['impersonate'] = res['profile']
        # an error answer keeps every header (like the urllib 403 path) - botprotection.detect() needs them
        self.fillHeaderItems(metadata, res['headers'], collectAllHeaders=params.get('collect_all_headers') or status >= 400)
        if params.get('impersonate') and 200 <= status < 400:
            # the host asked for it and it works: covers / files fetched later without the host's params too
            _impersonateRegister(url)
        return res

    def getPageImpersonate(self, url, params={}, post_data=None):
        '''getPage() through curl-impersonate (Chrome's TLS/HTTP2 fingerprint and its own User-Agent /
        Accept* / sec-ch-ua headers, the host's other headers are sent as given). Same (sts, data) and
        metadata convention as the urllib path. Returns None when the binary is missing or cannot run,
        the caller then uses the normal path.
        return_data False: like urllib, data is a response object (read(), geturl(), getcode(), info())
        over a temporary file that close() removes; an HTTP error gives (False, that object).'''
        params = dict(params)
        if not params.get('return_data', True):
            return self._getResponseImpersonate(url, params, post_data)
        params['return_data'] = True

        res = self._impersonateFetch(url, params, post_data)
        if res is None:
            return None
        if res is False:
            return False, None
        metadata = self.meta
        status = res['status']

        if 200 <= status < 400:
            sts = True  # 3xx only arrives with no_redirection - like urllib's NoRedirection
        else:
            sts = False
            for ignoreCodeRange in params.get('ignore_http_code_ranges', [(404, 404), (500, 500)]):
                if ignoreCodeRange[0] <= status <= ignoreCodeRange[1]:
                    sts = True
                    break

        body = res['body']
        if status == 403:
            metadata['body_head'] = body[:65536].decode('utf-8', 'ignore')
        data, metadata = self.handleCharset(params, body, metadata)
        if isinstance(data, bytes):
            data = strDecode(data, 'ignore')

        printDBG('pCommon - getPageImpersonate() return -> sts: %s, HTTP %s, url: %s' % (sts, status, maskSecrets(metadata['url'])))
        if params.get('with_metadata', False) or not sts:
            data = strwithmeta(data, metadata)
        return sts, data

    def _getResponseImpersonate(self, url, params, post_data=None):
        '''getPage(..., {'return_data': False}) through curl-impersonate, see getPageImpersonate'''
        if 'max_data_size' in params:
            printDBG('pCommon - getPageImpersonate() return_data False is not accepted with max_data_size')
            return False, None  # urllib path: getURLRequestData raises, getPage returns (False, None)
        fd, bodyFile = tempfile.mkstemp(prefix='e2i_impdl_', dir=GetTmpDir())
        os.close(fd)
        try:
            res = self._impersonateFetch(url, params, post_data, outFile=bodyFile)
            if not res:
                rm(bodyFile)
                return None if res is None else (False, None)
            status = res['status']
            if status == 403:
                # like the urllib path: what identifies the protection system, the text "Access Forbidden"
                with open(bodyFile, 'rb') as f:
                    self.meta['body_head'] = f.read(65536).decode('utf-8', 'ignore')
                rm(bodyFile)
                return False, strwithmeta(_('Access Forbidden'), self.meta)
            response = ImpersonateResponse(bodyFile, res['url'], status, res['headers'])
        except Exception:
            printExc()
            rm(bodyFile)
            return False, None
        printDBG('pCommon - getPageImpersonate() return_data False -> HTTP %s, %d bytes, url: %s' % (status, res['size'], maskSecrets(res['url'])))
        # urllib raises HTTPError (readable, .code) for every status >= 400 here
        return (200 <= status < 400), response

    def _saveWebFileImpersonate(self, file_path, url, addParams, post_data=None):
        '''saveWebFile() through curl-impersonate: curl writes the body to file_path. Same result dict
        ({'sts', 'fsize', 'reason'}) and checks (HTTP status, maintype / subtypes, check_first_bytes,
        WebP/AVIF conversion) as the pycurl / urllib paths; a failed download leaves no file behind.
        None when the binary is missing or cannot run - the caller then uses the normal path.'''
        params = dict(addParams)
        params.pop('max_data_size', None)
        res = self._impersonateFetch(url, params, post_data, outFile=file_path, caller='saveWebFileImpersonate')
        if res is None:
            return None
        reason = ''
        size = 0
        if res is False:
            error = self.meta.get('curl_error')
            reason = ('curl error %r' % (error,)) if error else 'no connection (see the error above)'
        else:
            status = res['status']
            size = res['size']
            self.meta['size_download'] = size
            contentType = self.meta.get('content-type', res['headers'].get('content-type', ''))
            mimeType = contentType.split(';', 1)[0].strip().lower()
            mainType = params.get('check_maintype', params.get('maintype'))
            subTypes = params.get('check_subtypes', params.get('subtypes'))
            if not (200 <= status < 400):
                reason = 'HTTP %s' % status
            elif mainType is not None and mainType != mimeType.split('/', 1)[0]:
                reason = 'wrong content-type %s' % contentType
            elif subTypes is not None and mimeType.split('/', 1)[-1] not in subTypes:
                reason = 'wrong content-type %s' % contentType
            elif size <= 0:
                reason = 'empty answer'
            elif params.get('check_first_bytes'):
                with open(file_path, 'rb') as f:
                    head = f.read(16)
                if not MatchFirstBytes(head, params['check_first_bytes']):
                    reason = 'not a picture, content-type[%s] first bytes %r' % (contentType, head)
        if reason:
            printDBG('pCommon - saveWebFileImpersonate() failed: %s' % reason)
            if os.path.exists(file_path):
                rm(file_path)
            return {'sts': False, 'fsize': 0, 'reason': reason}

        # decode WebP/AVIF to jpeg/png (image downloads, or a .webp URL) like the other paths
        if (url.endswith('.webp') or 'check_first_bytes' in params or mimeType == 'image/webp') and IsConvertibleImage(file_path):
            self.convertWebp(file_path, png=params.get('webp_convert_to_png', False))
        printDBG('pCommon - saveWebFileImpersonate() -> %d bytes, HTTP %s, url: %s' % (size, status, maskSecrets(res['url'])))
        return {'sts': True, 'fsize': size, 'reason': ''}

    def _retryImpersonate(self, baseUrl, params, post_data, data):
        '''getPageCFProtection: the answer is a Cloudflare challenge - ask again as Chrome (curl-impersonate).
        Returns (sts, data) when that got a normal answer (the domain then keeps using it), else None.'''
        if params.get('impersonate', None) is not None:
            return None  # the host asked for it (already tried) or switched it off
        domain = _impersonateDomain(baseUrl)
        registered = _impersonateMatch(baseUrl)
        if registered:
            # the remembered domain asks again: a cf_clearance from MyE2i only works with the solving
            # browser's User-Agent, which the impersonated request would not send
            printDBG('PROTECTION: %s challenges curl-impersonate now as well, back to the normal path' % registered)
            _impersonateDomains.discard(registered)
            return None
        if not curlimpersonate.getImpersonateBinary():
            return None
        try:
            from Plugins.Extensions.IPTVPlayer.libs.botprotection import detect as detectProtection, KIND_CLOUDFLARE
            failMeta = getattr(data, 'meta', None) or {}
            found = detectProtection(failMeta.get('status_code', 0), failMeta, failMeta.get('body_head') or (data if isinstance(data, str) else ''), failMeta.get('url', baseUrl))
            if found is None or found.kind != KIND_CLOUDFLARE:
                return None
            printDBG('PROTECTION: %s - retrying with curl-impersonate' % found.describe())
            newParams = dict(params)
            newParams['impersonate'] = True
            sts2, data2 = self.getPage(baseUrl, newParams, post_data)
            meta2 = getattr(data2, 'meta', None) or {}
            if data2 is None or not meta2.get('impersonate'):
                printDBG('PROTECTION: curl-impersonate gave no answer')
                return None
            if not sts2:
                found2 = detectProtection(meta2.get('status_code', 0), meta2, meta2.get('body_head') or data2, meta2.get('url', baseUrl))
                if found2 is not None:
                    printDBG('PROTECTION: curl-impersonate stopped too: %s' % found2.describe())
                    return None
            _impersonateDomains.add(domain)
            printDBG('impersonate: %s passes as Chrome (%s)' % (domain, meta2.get('impersonate')))
            return sts2, data2
        except Exception:
            printExc()
        return None

    def getPage(self, url, addParams={}, post_data=None):
        ''' wraps getURLRequestData '''

        # impersonate: Chrome's TLS/HTTP2 fingerprint through curl-impersonate (True from the host, or a
        # registered domain, see _impersonateDomains; False keeps the normal path). Without the binary or
        # with multipart data the normal path below is used.
        if self._useImpersonate(url, addParams) and not addParams.get('multipart_post_data', False):
            result = self.getPageImpersonate(url, addParams, post_data)
            if result is not None:
                return result

        # if curl should be used and can be used
        if addParams.get('return_data', True) and not addParams.get('CFProtection', False) and self.usePyCurl():
            return self.getPageWithPyCurl(url, addParams, post_data)

        try:
            addParams['url'] = url
            if 'return_data' not in addParams:
                addParams['return_data'] = True
            response = self.getURLRequestData(addParams, post_data)
            status = True
        except urllib2_HTTPError as e:
            try:
                # an HTTP error answer (403 Cloudflare challenge, 404 ...) is handled below - its traceback says nothing more
                printDBG('pCommon - getPage() -> HTTP %s [%s]' % (e.code, maskSecrets(url)))
                if e.code == 308:
                    return self.getPage(e.fp.info().get('Location', ''), addParams, post_data)
                status = False
                response = e
                if e.code == 403:
                    # keep what identifies the protection system that answered
                    # (see libs/botprotection.py); the returned text is unchanged
                    meta403 = {'status_code': 403}
                    try:
                        meta403['url'] = e.fp.geturl()
                        self.fillHeaderItems(meta403, e.fp.info(), True, collectAllHeaders=True)
                        head = self._readHttpResponse(e.fp, 65536)
                        if e.fp.info().get('Content-Encoding', '') == 'gzip':
                            head = DecodeGzipped(head)
                        if isinstance(head, bytes):
                            head = head.decode('utf-8', 'ignore')
                        meta403['body_head'] = head
                    except Exception:
                        printExc()
                    return (status, strwithmeta(_('Access Forbidden'), meta403))
                if addParams.get('return_data', False):
                    self.meta = {}
                    metadata = self.meta
                    metadata['url'] = e.fp.geturl()
                    metadata['status_code'] = e.code
                    self.fillHeaderItems(metadata, e.fp.info(), True, collectAllHeaders=addParams.get('collect_all_headers'))

                    data = self._readHttpResponse(e.fp, addParams.get('max_data_size', -1))
                    if e.fp.info().get('Content-Encoding', '') == 'gzip':
                        data = DecodeGzipped(data)

                    data, metadata = self.handleCharset(addParams, data, metadata)
                    response = strwithmeta(data, metadata)
                    e.fp.close()
            except Exception:
                printExc()
        except urllib2_URLError as e:
            printExc()
            errorMsg = str(e)
            if 'ssl_protocol' not in addParams and 'TLSV1_ALERT_PROTOCOL_VERSION' in errorMsg:
                    try:
                        newParams = dict(addParams)
                        newParams['ssl_protocol'] = 'TLSv1_2'
                        return self.getPage(url, newParams, post_data)
                    except Exception:
                        pass
            if 'VERSION' in errorMsg:
                self.reportHttpsError('version', url, errorMsg)
            elif 'VERIFY_FAILED' in errorMsg:
                self.reportHttpsError('verify', url, errorMsg)
            elif 'SSL' in errorMsg or 'unknown url type: https' in errorMsg: #GET_SERVER_HELLO
                self.reportHttpsError('other', url, errorMsg)

            response = None
            status = False

        except Exception:
            printExc()
            response = None
            status = False

        if addParams['return_data'] and status and not isinstance(response, basestring):
            status = False

        return (status, response)

    def getPageCFProtection(self, baseUrl, params=None, post_data=None):
        if params is None:
            params = {}  # a fresh dict per call: a shared default would keep header/cookies of an earlier site
        cf_user = params.get('header', {}).get('User-Agent', '')
        # the User-Agent that solved an earlier browser check for this cookie jar (see botprotection.py)
        from Plugins.Extensions.IPTVPlayer.libs.botprotection import remembered_user_agent, remember_user_agent
        solvedUserAgent = remembered_user_agent(params.get('cookiefile', ''))
        if solvedUserAgent:
            cf_user = solvedUserAgent
        header = {'Referer': baseUrl, 'User-Agent': cf_user, 'Accept-Encoding': 'text'}
        header.update(params.get('header', {}))
        if solvedUserAgent:
            header['User-Agent'] = solvedUserAgent
        params.update({'with_metadata': True, 'use_cookie': True, 'save_cookie': True, 'load_cookie': True, 'cookiefile': params.get('cookiefile', ''), 'header': header})
        params.update({'CFProtection': True})
        start_time = time.time()
        sts, data = self.getPage(baseUrl, params, post_data)

        impersonated = False
        if not sts and data is not None:
            # a Cloudflare challenge may only look at the TLS fingerprint - try once as Chrome first
            retried = self._retryImpersonate(baseUrl, params, post_data, data)
            if retried is not None:
                sts, data = retried
                impersonated = True

        if not impersonated and not sts and data is not None:
            solveMode = 'CF'
            try:
                from Plugins.Extensions.IPTVPlayer.libs.botprotection import detect as detectProtection, KIND_BLOCK, KIND_CAPTCHA, KIND_COOKIE_GATE
                failMeta = getattr(data, 'meta', None) or {}
                found = detectProtection(failMeta.get('status_code', 0), failMeta, failMeta.get('body_head') or (data if isinstance(data, str) else ''), failMeta.get('url', baseUrl))
                if found:
                    printDBG('PROTECTION: %s' % found.describe())
                    if found.kind == KIND_BLOCK:
                        printDBG('PROTECTION: hard block - a browser check would not help, MyE2i not started')
                        blockMeta = dict(failMeta)
                        blockMeta['cf_user'] = cf_user
                        return sts, strwithmeta(data, blockMeta)
                    if found.kind in (KIND_COOKIE_GATE, KIND_CAPTCHA):
                        solveMode = 'COOKIES'
            except Exception:
                printExc()
            from Plugins.Extensions.IPTVPlayer.libs.recaptcha_mye2i import UnCaptchaReCaptcha
            recaptcha = UnCaptchaReCaptcha(lang=GetDefaultLang())
            token = recaptcha.processCaptcha(start_time, baseUrl, captchaType=solveMode)
            if token != '':
                r = json_loads(base64.b64decode(token))
                printDBG('>>>>>>>>>>>>>>>>>>>>> CF token >>>>>>>>>>>>>>>>>>>>>>')
                printDBG(r)
                printDBG('<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
                if cf_user != r.get('user_agent', ''):
                    cf_user = r.get('user_agent', '')
                    config.plugins.iptvplayer.cloudflare_user = ConfigText(default="", fixed_size=False)
                    config.plugins.iptvplayer.cloudflare_user.value = cf_user
                    config.plugins.iptvplayer.cloudflare_user.save()
                    configfile.save()
                params['header']['User-Agent'] = cf_user
                if cf_user and r.get('cookie'):
                    remember_user_agent(params.get('cookiefile', ''), cf_user)

                cookies = r.get('cookie', [])
                if solveMode == 'COOKIES':
                    # generic mode: the browser sends every cookie it holds for the site
                    params['cookie_items'] = {c['name']: c['value'] for c in cookies if isinstance(c, dict) and c.get('name')}
                elif len(cookies) > 0:
                    try:
                        params['cookie_items'] = {'cf_clearance': cookies[0]['value']}
                    except Exception:
                        try:
                            params['cookie_items'] = {'cf_clearance': cookies['value']} # mye2i < 1.7
                        except Exception:
                            printDBG('missing cf_clearance value in received token')
                sts, data = self.getPage(baseUrl, params, post_data)
                if not sts:
                    printDBG('>>>>>>>>>>>>>>>> not sts returned data >>>>>>>>>>>>>>')
                    printDBG(data)
                    printDBG('<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')

        data = strwithmeta(data, {'cf_user': cf_user})

        return sts, data

    def convertWebp(self, file_path, png=False):
        # WebP (or AVIF) -> JPEG/PNG in place: Pillow when it can read the file, else ffmpeg
        printDBG("PCommon.convertWebp %s" % file_path)
        output_path = file_path + (".png" if png else ".jpg")
        if not os.path.exists(file_path):
            printDBG("PCommon.convertWebp file not exists %s" % file_path)
            return
        if os.path.exists(output_path):
            os.remove(output_path)
        if hasPIL:
            try:
                img = Image.open(file_path)
                if not png and img.mode not in ('RGB', 'L'):
                    # JPEG can't hold an alpha channel
                    img = img.convert('RGB')
                img.save(output_path, format="png" if png else "jpeg", quality=80)
                os.remove(file_path)
                move(output_path, file_path)
                return
            except Exception:
                # e.g. AVIF, or a PIL without WebP - ffmpeg may still read it
                printDBG("PCommon.convertWebp Pillow can't read %s, trying ffmpeg" % file_path)

        if IsExecutable('ffmpeg'):
            fp = "'%s'" % file_path.replace("'", "'\\''")
            op = "'%s'" % output_path.replace("'", "'\\''")
            command = "ffmpeg -y -i %s -frames:v 1 -update 1 %s && test -e %s && rm %s && mv %s %s " % (fp, op, op, fp, op, fp)
            printDBG("Send command %s" % command)
            if IsMainThread():
                self.cmd = iptv_system(command)
            else:
                # download thread (icons): wait, so the picture is converted before it is shown
                iptv_execute()(command)

    def saveWebFileWithPyCurl(self, file_path, url, add_params={}, post_data=None):
        bRet = False
        downDataSize = 0

        add_params['with_metadata'] = True
        add_params['save_to_file'] = file_path
        if 'maintype' in add_params:
            add_params['check_maintype'] = add_params.pop('maintype')
        if 'subtypes' in add_params:
            add_params['check_subtypes'] = add_params.pop('subtypes')

        sts, data = self.getPageWithPyCurl(url, add_params, post_data)
        reason = ''
        if sts:
            downDataSize = data.meta['size_download']
        else:
            rm(file_path)
            # for the caller's log: why nothing usable arrived
            meta = getattr(data, 'meta', {}) or {}
            if meta.get('abort_reason'):
                reason = meta['abort_reason']
            elif meta.get('pycurl_error'):
                reason = 'curl error %r' % (meta['pycurl_error'],)
            else:
                reason = 'HTTP %s' % meta.get('status_code', '?')
        return {'sts': sts, 'fsize': downDataSize, 'reason': reason}

    def saveWebFile(self, file_path, url, addParams={}, post_data=None):
        addParams = dict(addParams)

        outParams, postData = self.getParamsFromUrlWithMeta(url)
        addParams.update(outParams)
        if 'header' not in addParams and 'host' not in addParams:
            host = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
            header = {'User-Agent': host, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
            addParams['header'] = header
        addParams['return_data'] = False

        # Chrome's fingerprint (a host's impersonate=True, or a registered domain - covers, subtitles)
        if self._useImpersonate(url, addParams) and not addParams.get('multipart_post_data', False):
            ret = self._saveWebFileImpersonate(file_path, url, addParams, post_data)
            if ret is not None:
                return ret

        # if curl should and can be used
        if self.usePyCurl():
            return self.saveWebFileWithPyCurl(file_path, url, addParams, post_data)

        bRet = False
        downDataSize = 0
        dictRet = {}
        # for the caller's log: why nothing usable arrived
        reason = ''
        try:
            sts, downHandler = self.getPage(url, addParams, post_data)
            if not sts:
                meta = getattr(downHandler, 'meta', None) or {}
                code = getattr(downHandler, 'code', None) or meta.get('status_code')
                reason = ('HTTP %s' % code) if code else 'no connection (see the error above)'
            if downHandler == None or (not sts and not hasattr(downHandler, 'read')):
                # the request itself failed (e.g. invalid URL, no connection), nothing to read; an HTTPError
                # still has a body to read below (some servers send a picture with it)
                dictRet.update({'sts': False, 'fsize': 0, 'reason': reason or 'no answer'})
                return dictRet

            if addParams.get('ignore_content_length', False):
                meta = downHandler.info()
                contentLength = int(meta.getheaders("Content-Length")[0])
            else:
                contentLength = None

            checkFromFirstBytes = addParams.get('check_first_bytes', [])
            OK = True
            if 'maintype' in addParams:
                if isPY2():
                    if addParams['maintype'] != downHandler.headers.maintype:
                        printDBG("common.getFile wrong maintype! requested[%r], retrieved[%r]" % (addParams['maintype'], downHandler.headers.maintype))
                        if 0 == len(checkFromFirstBytes):
                            downHandler.close()
                        OK = False
                else: #PY3
                    #printDBG('!!!!! downHandler.headers: %s!!!!!' % downHandler.headers )
                    if addParams['maintype'] not in str(downHandler.headers): #silly catching Content-Type: image/png from header
                        printDBG("common.getFile wrong maintype! requested[%s], retrieved[%s]" % (addParams['maintype'], str(downHandler.headers)))
                        if 0 == len(checkFromFirstBytes):
                            downHandler.close()
                        OK = False

            if OK and 'subtypes' in addParams:
                OK = False
                #printDBG('!!!!! downHandler.headers: %s!!!!!' % downHandler.headers )
                for item in addParams['subtypes']:
                    #printDBG("saveWebFile() subtype='%s'" % item)
                    if isPY2():
                        if item == downHandler.headers.subtype:
                            OK = True
                            break
                    else: #PY3
                        if item in str(downHandler.headers):
                            printDBG("common.getFile found '%s' subtype in header" % item)
                            OK = True
                            break

            printDBG('saveWebFile() OK=%s, checkFromFirstBytes=%s' % (str(OK), checkFromFirstBytes))
            if OK or len(checkFromFirstBytes):
                blockSize = addParams.get('block_size', 8192)
                fileHandler = None
                gunzip = None
                try:
                    if (downHandler.info().get('Content-Encoding') or '').lower() == 'gzip':
                        # urllib does not undo a Content-Encoding - some image CDNs gzip even unasked
                        gunzip = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        contentLength = None
                except Exception:
                    printExc()
                while True:
                    CurrBuffer = downHandler.read(blockSize)
                    if gunzip != None:
                        if CurrBuffer:
                            CurrBuffer = gunzip.decompress(CurrBuffer)
                            if not CurrBuffer:
                                continue
                        else:
                            CurrBuffer = gunzip.flush()
                            gunzip = None

                    if len(checkFromFirstBytes):
                        printDBG('saveWebFile() buffer.startswith "%s"' % CurrBuffer[:5])
                        if not MatchFirstBytes(CurrBuffer, checkFromFirstBytes):
                            if CurrBuffer:
                                detail = 'not a picture, content-type[%s] first bytes %r' % (
                                    downHandler.info().get('Content-Type', ''), CurrBuffer[:16])
                            else:
                                detail = 'empty answer'
                            reason = (reason + ', ' if reason else '') + detail
                            break
                        checkFromFirstBytes = []

                    if not CurrBuffer:
                        break
                    downDataSize += len(CurrBuffer)
                    if len(CurrBuffer):
                        if fileHandler == None:
                            fileHandler = open(file_path, "wb")
                        fileHandler.write(CurrBuffer)
                if fileHandler != None:
                    fileHandler.close()
                downHandler.close()
                if None != contentLength:
                    if contentLength == downDataSize:
                        bRet = True
                    elif not reason:
                        reason = 'incomplete, %d of %d bytes' % (downDataSize, contentLength)
                elif downDataSize > 0:
                    bRet = True
                elif not reason:
                    reason = 'empty answer'

                # image downloads (icons): WebP/AVIF -> JPEG, the picture loader shows neither
                if bRet and 'check_first_bytes' in addParams and IsConvertibleImage(file_path):
                    self.convertWebp(file_path)
            elif not reason:
                reason = 'wrong content-type %s' % downHandler.info().get('Content-Type', '')
        except Exception as e:
            printExc("common.getFile download file exception")
            reason = (reason + ', ' if reason else '') + 'exception %r' % (e,)
        dictRet.update({'sts': bRet, 'fsize': downDataSize, 'reason': '' if bRet else reason})
        return dictRet

    def getUrllibSSLProtocolVersion(self, protocolName):
        if not isinstance(protocolName, basestring):
            GetIPTVNotify().push('getUrllibSSLProtocolVersion error. Please report this problem to iptvplayere2@gmail.com', 'error', 40)
            return protocolName
        if protocolName == 'TLSv1_2':
            return ssl.PROTOCOL_TLSv1_2
        elif protocolName == 'TLSv1_1':
            return ssl.PROTOCOL_TLSv1_1
        return None

    def getPyCurlSSLProtocolVersion(self, protocolName):
        if not isinstance(protocolName, basestring):
            GetIPTVNotify().push('getPyCurlSSLProtocolVersion error. Please report this problem to iptvplayere2@gmail.com', 'error', 40)
            return protocolName
        if protocolName == 'TLSv1_2':
            return pycurl.SSLVERSION_TLSv1_2
        elif protocolName == 'TLSv1_1':
            return pycurl.SSLVERSION_TLSv1_1
        return None

    def getURLRequestData(self, params={}, post_data=None):

        def urlOpen(req, customOpeners, timeout):
            #req = ensure_binary(req)
            # above line was added to resolve > "TypeError: POST data should be bytes, an iterable of bytes, or a file object. It cannot be of type str."
            # but it seems it breaks other scenarios
            # also documentation says req should be a string. :(
            # NEEDS FURTHER INVESTIGATION !!!

            if len(customOpeners) > 0:
                opener = urllib2_build_opener(*customOpeners)
                if timeout != None:
                    response = opener.open(req, timeout=timeout)
                else:
                    response = opener.open(req)
            else:
                if timeout != None:
                    response = urllib2_urlopen(req, timeout=timeout)
                else:
                    response = urllib2_urlopen(req)
            return response

        if IsMainThread():
            msg1 = _('It is not allowed to call getURLRequestData from main thread.')
            msg2 = _('You should never perform block I/O operations in the __init__.')
            GetIPTVNotify().push(' '.join([msg1, msg2]), 'error', 40)
            raise Exception("Wrong usage!")

        if 'max_data_size' in params and not params.get('return_data', False):
            raise Exception("return_data == False is not accepted with max_data_size.\nPlease also note that return_data == False is deprecated and not supported with PyCurl HTTP backend!")

        cj = cookielib.MozillaCookieJar()
        response = None
        req = None
        out_data = None
        opener = None
        self.meta = {}
        metadata = self.meta

        timeout = params.get('timeout', None)

        if 'host' in params:
            host = params['host']
        else:
            host = self.HOST

        if 'header' in params:
            headers = params['header']
        elif None != self.HEADER:
            headers = self.HEADER
        else:
            headers = {'User-Agent': host}

        if 'User-Agent' not in headers:
            headers['User-Agent'] = host

        printDBG('pCommon - getURLRequestData() -> params: ' + str(params))
        printDBG('pCommon - getURLRequestData() -> headers: ' + str(headers))

        customOpeners = []
        #cookie support
        if 'use_cookie' not in params and 'cookiefile' in params and ('load_cookie' in params or 'save_cookie' in params):
            params['use_cookie'] = True

        if params.get('use_cookie', False):
            if params.get('load_cookie', False):
                try:
                    cj.load(params['cookiefile'], ignore_discard=True)
                except IOError:
                    printDBG('Cookie file [%s] not exists' % params['cookiefile'])
                except Exception:
                    printExc()
            try:
                for cookieKey in list(params.get('cookie_items', {}).keys()):
                    printDBG("cookie_item[%s=%s]" % (cookieKey, params['cookie_items'][cookieKey]))
                    cookieItem = cookielib.Cookie(version=0, name=cookieKey, value=params['cookie_items'][cookieKey], port=None, port_specified=False, domain='', domain_specified=False, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
                    cj.set_cookie(cookieItem)
            except Exception:
                printExc()
            customOpeners.append(urllib2_HTTPCookieProcessor(cj))

        if params.get('no_redirection', False):
            customOpeners.append(NoRedirection())

        if None != params.get('ssl_protocol', None):
            sslProtoVer = self.getUrllibSSLProtocolVersion(params['ssl_protocol'])
        else:
            sslProtoVer = None
        # debug
        #customOpeners.append(urllib2_HTTPSHandler(debuglevel=1))
        #customOpeners.append(urllib2_HTTPHandler(debuglevel=1))
        if not IsHttpsCertValidationEnabled():
            try:
                if sslProtoVer != None:
                    ctx = ssl._create_unverified_context(sslProtoVer)
                else:
                    ctx = ssl._create_unverified_context()
                customOpeners.append(urllib2_HTTPSHandler(context=ctx))
            except Exception:
                pass
        elif sslProtoVer != None:
            ctx = ssl.SSLContext(sslProtoVer)
            customOpeners.append(urllib2_HTTPSHandler(context=ctx))

        #proxy support
        if self.useProxy:
            http_proxy = self.proxyURL
        else:
            http_proxy = ''
        #proxy from parameters (if available) overwrite default one
        if 'http_proxy' in params:
            http_proxy = params['http_proxy']
        if '' != http_proxy:
            printDBG('getURLRequestData USE PROXY')
            customOpeners.append(urllib2_ProxyHandler({"http": http_proxy}))
            customOpeners.append(urllib2_ProxyHandler({"https": http_proxy}))

        pageUrl = params['url']
        proxy_gateway = params.get('proxy_gateway', '')
        if proxy_gateway != '':
            pageUrl = proxy_gateway.format(urllib_quote_plus(pageUrl, ''))
        printDBG("pageUrl: [%s]" % pageUrl)
        #it seems sometimes iconmenager provides incorrectly formatted params dict
        #as a result pageUrl contains a lot of garbage like following
        #pageUrl: [https://yt3.ggpht.com/ytc/AMLnZu8d_ae-Ne1CeYtv1ARy9IngDnVVKh2nUaYg16tgqQ=s88-c-k-c0x00ffffff-no-rj","width":88,"height":88},{"url":"https://yt3.ggpht.com/ytc/AMLnZu8d_ae-Ne1CeYtv1ARy9IngDnVVKh2nUaYg16tgqQ=s176-c-k-c0x00ffffff-no-rj","width":176,"height":176}]},"trackingParams":"CCcQq6cCIhMIi-e74LeW-gIVyACJCh2OnAFM","accessibility":{"accessibilityData":{"label":"Pretending I Can't Sing In Public And Then Surprising Everyone😱 \"give me a kiss\" OUT NOW🌎🎵 Crash Adams 2 tygodnie temu"}}}},"nextItemButton":{"buttonRenderer":{"trackingParams":"CCYQqKQCIhMIi-e74LeW-gIVyACJCh2OnAFM"}},"prevItemButton":{"buttonRenderer":{"trackingParams":"CCUQqaQCIhMIi-e74LeW-gIVyACJCh2OnAFM"}},"style":"REEL_PLAYER_OVERLAY_STYLE_SHORTS","trackingParams":"CCQQsLUEIhMIi-e74LeW-gIVyACJCh2OnAFM"}},"params":"CBYwAg%3D%3D","sequenceProvider":"REEL_WATCH_SEQUENCE_PROVIDER_RPC","sequenceParams":"CgtXUC1oSE16QmxmUSoCGBY%3D"}},"ownerBadges":[{"metadataBadgeRenderer":{"icon":{"iconType":"OFFICIAL_ARTIST_BADGE"},"style":"BADGE_STYLE_TYPE_VERIFIED_ARTIST","tooltip":"Oficjalny kanał wykonawcy","trackingParams":"CCAQnaQHGBoiEwiL57vgt5b6AhXIAIkKHY6cAUw=","accessibilityData":{"label":"Oficjalny kanał wykonawcy"}}}],"ownerText":{"runs":[{"text":"Crash Adams","navigationEndpoint":{"clickTrackingParams":"CCAQnaQHGBoiEwiL57vgt5b6AhXIAIkKHY6cAUw=","commandMetadata":{"webCommandMetadata":{"url":"/channel/UCAxCk_CU0lnz6vJyslY9-Tw","webPageType":"WEB_PAGE_TYPE_CHANNEL","rootVe":3611,"apiUrl":"/youtubei/v1/browse"}},"browseEndpoint":{"browseId":"UCAxCk_CU0lnz6vJyslY9-Tw","canonicalBaseUrl":"/channel/UCAxCk_CU0lnz6vJyslY9-Tw"}}}]},"shortBylineText":{"runs":[{"text":"Crash Adams","navigationEndpoint":{"clickTrackingParams":"CCAQnaQHGBoiEwiL57vgt5b6AhXIAIkKHY6cAUw=","commandMetadata":{"webCommandMetadata":{"url":"/channel/UCAxCk_CU0lnz6vJyslY9-Tw","webPageType":"WEB_PAGE_TYPE_CHANNEL","rootVe":3611,"apiUrl":"/youtubei/v1/browse"}},"browseEndpoint":{"browseId":"UCAxCk_CU0lnz6vJyslY9-Tw","canonicalBaseUrl":"/channel/UCAxCk_CU0lnz6vJyslY9-Tw"}}}]},"trackingParams":"CCAQnaQHGBoiEwiL57vgt5b6AhXIAIkKHY6cAUxA9KuG5syj6P9Y","showActionMenu":false,"shortViewCountText":{"accessibility":{"accessibilityData":{"label":"14 milionów wyświetleń"}},"simpleText":"14 mln wyświetleń"},"menu":{"menuRenderer":{"items":[{"menuServiceItemRenderer":{"text":{"runs":[{"text":"Dodaj do kolejki"}]},"icon":{"iconType":"ADD_TO_QUEUE_TAIL"},"serviceEndpoint":{"clickTrackingParams":"CCMQ_pgEGAciEwiL57vgt5b6AhXIAIkKHY6cAUw=","commandMetadata":{"webCommandMetadata":{"sendPost":true}},"signalServiceEndpoint":{"signal":"CLIENT_SIGNAL","actions":[{"clickTrackingParams":"CCMQ_pgEGAciEwiL57vgt5b6AhXIAIkKHY6cAUw=","addToPlaylistCommand":{"openMiniplayer":true,"videoId":"WP-hHMzBlfQ","listType":"PLAYLIST_EDIT_LIST_TYPE_QUEUE","onCreateListCommand":{"clickTrackingParams":"CCMQ_pgEGAciEwiL57vgt5b6AhXIAIkKHY6cAUw=","commandMetadata":{"webCommandMetadata":{"sendPost":true,"apiUrl":"/youtubei/v1/playlist/create"}},"createPlaylistServiceEndpoint":{"videoIds":["WP-hHMzBlfQ"],"params":"CAQ%3D"}},"videoIds":["WP-hHMzBlfQ"]}}]}},"trackingParams":"CCMQ_pgEGAciEwiL57vgt5b6AhXIAIkKHY6cAUw="}}],"trackingParams":"CCAQnaQHGBoiEwiL57vgt5b6AhXIAIkKHY6cAUw=","accessibility":{"accessibilityData":{"label":"Menu czynności"}}}},"channelThumbnailSupportedRenderers":{"channelThumbnailWithLinkRenderer":{"thumbnail":{"thumbnails":[{"url":"https://yt3.ggpht.com/ytc/AMLnZu8d_ae-Ne1CeYtv1ARy9IngDnVVKh2nUaYg16tgqQ=s88-c-k-c0x00ffffff-no-rj","width":68,"height":68}]},"navigationEndpoint":{"clickTrackingParams":"CCAQnaQHGBoiEwiL57vgt5b6AhXIAIkKHY6cAUw=","commandMetadata":{"webCommandMetadata":{"url":"/channel/UCAxCk_CU0lnz6vJyslY9-Tw","webPageType":"WEB_PAGE_TYPE_CHANNEL","rootVe":3611,"apiUrl":"/youtubei/v1/browse"}},"browseEndpoint":{"browseId":"UCAxCk_CU0lnz6vJyslY9-Tw"}},"accessibility":{"accessibilityData":{"label":"Przejdź na kanał"}}}},"thumbnailOverlays":[{"thumbnailOverlayTimeStatusRenderer":{"text":{"accessibility":{"accessibilityData":{"label":"Shorts"}},"simpleText":"SHORTS"},"style":"SHORTS","icon":{"iconType":"YOUTUBE_SHORTS_FILL_NO_TRIANGLE_RED_16"}}},{"thumbnailOverlayToggleButtonRenderer":{"isToggled":false,"untoggledIcon":{"iconType":"WATCH_LATER"},"toggledIcon":{"iconType":"CHECK"},"untoggledTooltip":"Do obejrzenia","toggledTooltip":"Dodano","untoggledServiceEndpoint":{"clickTrackingParams":"CCIQ-ecDGAIiEwiL57vgt5b6AhXIAIkKHY6cAUw=","commandMetadata":{"webCommandMetadata":{"sendPost":true,"apiUrl":"/youtubei/v1/browse/edit_playlist"}},"playlistEditEndpoint":{"playlistId":"WL","actions":[{"addedVideoId":"WP-hHMzBlfQ","action":"ACTION_ADD_VIDEO"}]}},"toggledServiceEndpoint":{"clickTrackingParams":"CCIQ-ecDGAIiEwiL57vgt5b6AhXIAIkKHY6cAUw=","commandMetadata":{"webCommandMetadata":{"sendPost":true,"apiUrl":"/youtubei/v1/browse/edit_playlist"}},"playlistEditEndpoint":{"playlistId":"WL","actions":[{"action":"ACTION_REMOVE_VIDEO_BY_VIDEO_ID","removedVideoId":"WP-hHMzBlfQ"}]}},"untoggledAccessibility":{"accessibilityData":{"label":"Do obejrzenia"}},"toggledAccessibility":{"accessibilityData":{"label":"Dodano"}},"trackingParams":"CCIQ-ecDGAIiEwiL57vgt5b6AhXIAIkKHY6cAUw="}},{"thumbnailOverlayToggleButtonRenderer":{"untoggledIcon":{"iconType":"ADD_TO_QUEUE_TAIL"},"toggledIcon":{"iconType":"PLAYLIST_ADD_CHECK"},"untoggledTooltip":"Dodaj do kolejki","toggledTooltip":"Dodano","untoggledServiceEndpoint":{"clickTrackingParams":"CCEQx-wEGAMiEwiL57vgt5b6AhXIAIkKHY6cAUw=","commandMetadata":{"webCommandMetadata":{"sendPost":true}},"signalServiceEndpoint":{"signal":"CLIENT_SIGNAL","actions":[{"clickTrackingParams":"CCEQx-wEGAMiEwiL57vgt5b6AhXIAIkKHY6cAUw=","addToPlaylistCommand":{"openMiniplayer":true,"videoId":"WP-hHMzBlfQ","listType":"PLAYLIST_EDIT_LIST_TYPE_QUEUE","onCreateListCommand":{"clickTrackingParams":"CCEQx-wEGAMiEwiL57vgt5b6AhXIAIkKHY6cAUw=","commandMetadata":{"webCommandMetadata":{"sendPost":true,"apiUrl":"/youtubei/v1/playlist/create"}},"createPlaylistServiceEndpoint":{"videoIds":["WP-hHMzBlfQ"],"params":"CAQ%3D"}},"videoIds":["WP-hHMzBlfQ"]}}]}},"untoggledAccessibility":{"accessibilityData":{"label":"Dodaj do kolejki"}},"toggledAccessibility":{"accessibilityData":{"label":"Dodano"}},"trackingParams":"CCEQx-wEGAMiEwiL57vgt5b6AhXIAIkKHY6cAUw="}},{"thumbnailOverlayNowPlayingRenderer":{"text":{"runs":[{"text":"Teraz odtwarzane"}]}}}]}},{"videoRenderer":{"videoId":"1hkdTiMj_M4","thumbnail":{"thumbnails":[{"url":"https://i.ytimg.com/vi/1hkdTiMj_M4/hqdefault.jpg?sqp=-oaymwEbCNIBEHZIVfKriqkDDggBFQAAiEIYAXABwAEG\u0026rs=AOn4CLAP9P5vUJaPX3ebR7b0yV33Hc5KSw","width":210,"height":118},{"url":"https://i.ytimg.com/vi/1hkdTiMj_M4/hqdefault.jpg?sqp=-oaymwEcCPYBEIoBSFXyq4qpAw4IARUAAIhCGAFwAcABBg]
        #IconMenager.processDQ should be analyzed more deeply, now silly workarround
        if '","' in pageUrl: # points incorrectly formatted dict or list
            pageUrl = pageUrl.split('"', 1)[0] #" is incorrect char for url, shouldn't be there so removing it and everything after it
            printDBG("CORRECTED pageUrl: [%s]" % pageUrl)

        if None != post_data:
            #post_dataTxt = {}
            #for item in post_data:
            #    if 'username' in item.lower(): post_dataTxt[item] = 'userName'
            #    elif 'password' in item.lower(): post_dataTxt[item] = 'userPassword'
            #    elif 'token' in item.lower(): post_dataTxt[item] = 'userToken'
            #    else: post_dataTxt[item] = post_data[item]
            #printDBG('pCommon - getURLRequestData() -> post data: ' + str(post_dataTxt))
            printDBG('pCommon - getURLRequestData() -> post data: ' + str(post_data))
            if params.get('raw_post_data', False):
                dataPost = post_data
            elif params.get('multipart_post_data', False):
                customOpeners.append(MultipartPostHandler())
                dataPost = post_data
            else:
                dataPost = urllib_urlencode(post_data)

            dataPost = ensure_binary(dataPost)
            req = urllib2_Request(pageUrl, dataPost, headers)
        else:
            req = urllib2_Request(pageUrl, None, headers)

        if not params.get('return_data', False):
            out_data = urlOpen(req, customOpeners, timeout)
        else:
            gzip_encoding = False
            try:
                response = urlOpen(req, customOpeners, timeout)
                if response.info().get('Content-Encoding') == 'gzip':
                    gzip_encoding = True
                try:
                    metadata['url'] = response.geturl()
                    metadata['status_code'] = response.getcode()
                    self.fillHeaderItems(metadata, response.info(), True, collectAllHeaders=params.get('collect_all_headers'))
                except Exception:
                    pass

                max = params.get('max_data_size', -1)
                data = self._readHttpResponse(response, max)
                response.close()
            except urllib2_HTTPError as e:
                ignoreCodeRanges = params.get('ignore_http_code_ranges', [(404, 404), (500, 500)])
                ignoreCode = False
                metadata['status_code'] = e.code
                for ignoreCodeRange in ignoreCodeRanges:
                    if e.code >= ignoreCodeRange[0] and e.code <= ignoreCodeRange[1]:
                        ignoreCode = True
                        break

                if ignoreCode:
                    printDBG('!!!!!!!! %s: getURLRequestData - handled' % e.code)
                    if e.fp.info().get('Content-Encoding', '') == 'gzip':
                        gzip_encoding = True
                    try:
                        metadata['url'] = e.fp.geturl()
                        self.fillHeaderItems(metadata, e.fp.info(), True, collectAllHeaders=params.get('collect_all_headers'))
                    except Exception:
                        pass
                    max = params.get('max_data_size', -1)
                    data = self._readHttpResponse(e.fp, max)
                    #e.msg
                    #e.headers
                elif e.code == 503:
                    if params.get('use_cookie', False):
                        new_cookie = e.fp.info().get('Set-Cookie', '')
                        printDBG("> new_cookie[%s]" % new_cookie)
                        cj.save(params['cookiefile'], ignore_discard=True)
                    raise e
                else:
                    if e.code in [300, 302, 303, 307] and params.get('use_cookie', False) and params.get('save_cookie', False):
                        new_cookie = e.fp.info().get('Set-Cookie', '')
                        printDBG("> new_cookie[%s]" % new_cookie)
                        #for cookieKey in params.get('cookie_items', {}).keys():
                        #    cj.clear('', '/', cookieKey)
                        cj.save(params['cookiefile'], ignore_discard=True)
                    raise e
            try:
                if gzip_encoding:
                    printDBG('Content-Encoding == gzip')
                    out_data = DecodeGzipped(data)
                else:
                    out_data = data
            except Exception as e:
                printExc()
                if params.get('max_data_size', -1) == -1:
                    msg1 = _("Critical Error – Content-Encoding gzip cannot be handled!")
                    msg2 = _("Last error:\n%s" % str(e))
                    GetIPTVNotify().push('%s\n\n%s' % (msg1, msg2), 'error', 20)
                out_data = data

        if params.get('use_cookie', False) and params.get('save_cookie', False):
            try:
                cj.save(params['cookiefile'], ignore_discard=True)
            except Exception as e:
                printExc()
                raise e

        out_data, metadata = self.handleCharset(params, out_data, metadata)
        if params.get('with_metadata', False) and params.get('return_data', False):
            out_data = strwithmeta(out_data, metadata)

        return out_data

    def handleCharset(self, params, data, metadata):
        try:
            if params.get('return_data', False) and params.get('convert_charset', True):
                encoding = ''
                if 'content-type' in metadata:
                    encoding = self.ph.getSearchGroups(metadata['content-type'], r'''charset=([A-Za-z0-9\-]+)''', 1, True)[0].strip().upper()

                if encoding == '' and params.get('search_charset', False):
                    encoding = self.ph.getSearchGroups(strDecode(data, 'ignore'), '''(<meta[^>]+?Content-Type[^>]+?>)''', ignoreCase=True)[0]
                    encoding = self.ph.getSearchGroups(encoding, r'''charset=([A-Za-z0-9\-]+)''', 1, True)[0].strip().upper()
                if encoding not in ['', 'UTF-8']:
                    printDBG(">> encoding[%s]" % encoding)
                    try:
                        if isPY2():
                            data = data.decode(encoding).encode('UTF-8')
                        else:
                            data = data.decode(encoding)
                    except Exception:
                        printExc()
                    metadata['orig_charset'] = encoding
                else:
                    try:
                        data = strDecode(data)
                    except Exception:
                        data = strDecode(data, 'ignore')
        except Exception:
            printExc()
        return data, metadata

    def urlEncodeNonAscii(self, b):
        return re.sub(b'[\x80-\xFF]', lambda c: '%%%02x' % ord(c.group(0)), b)

    def iriToUri(self, iri):
        try:
            if isPY2() or isinstance(iri, bytes):
                iri = iri.decode('utf-8')
            parts = urlparse(iri)
            encodedParts = []
            for parti, part in enumerate(parts):
                newPart = part
                try:
                    if parti == 1:
                        newPart = part.encode('idna')
                    else:
                        newPart = self.urlEncodeNonAscii(part.encode('utf-8'))
                except Exception:
                    printExc()
                encodedParts.append(ensure_str(newPart))
            return urlunparse(encodedParts)
        except Exception:
            printExc()
        return iri

    def makeABCList(self, tab=['0 - 9']):
        strTab = list(tab)
        for i in range(65, 91):
            strTab.append(str(unichr(i)))
        return strTab

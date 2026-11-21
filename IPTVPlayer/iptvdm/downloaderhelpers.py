# -*- coding: utf-8 -*-
# IPTV download manager API
# # added: 07.08.2026 - Shared helpers for Downloader: Py2/Py3 safe text & path handling, shell quoting, and the sidecar, (.txt description + .jpg poster). - Kamikaze24
# 21.11.2026 - H264_FIX_OPTS / h264FixRefused(): downloads of "Constrained High" H.264 play on the boxes;
#   fixMkvH264Header(): an MKV with each SPS / PPS twice in its H.264 header plays in the Enigma2 media player.
###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc, eConnectCallback, GetNice, E2PrioFix
###################################################
# FOREIGN import
###################################################
from Tools.BoundFunction import boundFunction
from Components.config import config
from enigma import eConsoleAppContainer
import os
import signal
import struct
import threading
import time
import zlib
###################################################

try:
    text_type = unicode
    binary_type = str
    string_types = (basestring,)
except NameError:
    text_type = str
    binary_type = bytes
    string_types = (str, bytes)

# H.264 whose SPS sets constraint_set4 + constraint_set5 ("Constrained High", BongaCams rooms ...): the Broadcom
# decoders of the boxes give sound without a picture. ffmpeg's h264_metadata filter (ffmpeg 5.0+) sets both flags to 0
# in the copy - a rewrite of the stream headers, no re-encoding. ffmpeg stops at once on other video codecs (HEVC ...)
# and older builds do not know the option: the run goes again without it (h264FixRefused)
H264_FIX_OPTS = ('-bsf:v', 'h264_metadata=zero_new_constraint_set_flags=1')


def h264FixRefused(text):
    # ffmpeg's output: "... is not supported by the bitstream filter 'h264_metadata'", "Error initializing bitstream
    # filter", "Option zero_new_constraint_set_flags not found"
    text = ensureText(text or '')
    return 'bitstream filter' in text or 'zero_new_constraint_set_flags' in text


# Matroska element ids read by fixMkvH264Header()
_MKV_SEGMENT, _MKV_TRACKS, _MKV_CLUSTER = 0x18538067, 0x1654AE6B, 0x1F43B675
_MKV_TRACKENTRY, _MKV_CODECID, _MKV_CODECPRIVATE, _MKV_CRC32, _MKV_VOID = 0xAE, 0x86, 0x63A2, 0xBF, 0xEC
_MKV_HEAD_BYTES = 1048576


def _ebmlVint(buf, pos, maxLen):
    # (value without the length marker, length, all value bits set = unknown size)
    first = buf[pos]
    length = 1
    mask = 0x80
    while length <= maxLen and not first & mask:
        mask >>= 1
        length += 1
    if length > maxLen or pos + length > len(buf):
        raise ValueError('bad EBML number at %d' % pos)
    value = first & (mask - 1)
    for i in range(1, length):
        value = (value << 8) | buf[pos + i]
    return value, length, value == (1 << (7 * length)) - 1


def _ebmlElement(buf, pos):
    # (id with its marker, start of the data, size of the data or -1 when unknown)
    _unused, idLen, _unused = _ebmlVint(buf, pos, 4)
    elementId = 0
    for i in range(idLen):
        elementId = (elementId << 8) | buf[pos + i]
    size, sizeLen, unknown = _ebmlVint(buf, pos + idLen, 8)
    return elementId, pos + idLen + sizeLen, -1 if unknown else size


def _ebmlSizeField(value, length):
    # the EBML size field of the given length
    out = bytearray(length)
    value |= 1 << (7 * length)
    for i in range(length - 1, -1, -1):
        out[i] = value & 0xFF
        value >>= 8
    return out


def _dedupeAvcC(data):
    # AVCDecoderConfigurationRecord with each SPS / PPS once, None when it has no duplicates or is not one
    if len(data) < 7 or data[0] != 1:
        return None
    pos = 6
    groups = []
    for count in (data[5] & 0x1F, None):
        if count is None:
            if pos >= len(data):
                return None
            count = data[pos]
            pos += 1
        units = []
        for _unused in range(count):
            if pos + 2 > len(data):
                return None
            length = (data[pos] << 8) | data[pos + 1]
            unit = bytes(data[pos + 2:pos + 2 + length])
            if len(unit) != length:
                return None
            if unit not in units:
                units.append(unit)
            pos += 2 + length
        groups.append((count, units))
    if all(count == len(units) for count, units in groups):
        return None
    out = bytearray(data[:5])
    out.append(0xE0 | len(groups[0][1]))
    for unit in groups[0][1]:
        out += bytearray(((len(unit) >> 8) & 0xFF, len(unit) & 0xFF)) + bytearray(unit)
    out.append(len(groups[1][1]))
    for unit in groups[1][1]:
        out += bytearray(((len(unit) >> 8) & 0xFF, len(unit) & 0xFF)) + bytearray(unit)
    # the extension of the High profiles (chroma format, bit depth, SPS ext) stays as it is
    out += data[pos:]
    return out


def fixMkvH264Header(filePath):
    # An encoder that sends every SPS / PPS twice in front of a key frame (BongaCams rooms ...): ffmpeg puts both
    # copies into the H.264 header of an MKV (CodecPrivate), and the dvbvideosink of the boxes rejects it ("codec_data
    # too short", Enigma2 media player without a picture, box test 21.11.2026). Each SPS / PPS once again, in place:
    # the bytes set free become an EBML Void element, so no size or offset in the file changes; a CRC-32 of the
    # Tracks element is written again. Only touches the file when there are duplicates. Returns True when it did.
    try:
        path = fsPath(filePath)
        if not str(path).lower().endswith('.mkv') or not os.path.isfile(path):
            return False
        with open(path, 'rb') as f:
            buf = bytearray(f.read(_MKV_HEAD_BYTES))
        elementId, pos, size = _ebmlElement(buf, 0)
        pos += size  # EBML header
        elementId, pos, size = _ebmlElement(buf, pos)
        if elementId != _MKV_SEGMENT:
            return False
        segmentEnd = len(buf) if size < 0 else min(len(buf), pos + size)
        tracks = None
        while pos < segmentEnd:
            elementId, dataPos, size = _ebmlElement(buf, pos)
            if elementId == _MKV_CLUSTER or size < 0:
                break
            if elementId == _MKV_TRACKS:
                tracks = (dataPos, size)
                break
            pos = dataPos + size
        if tracks is None or tracks[0] + tracks[1] > len(buf):
            return False
        tracksPos, tracksSize = tracks
        tracksEnd = tracksPos + tracksSize
        changed = False
        crcPos = None
        pos = tracksPos
        while pos < tracksEnd:
            elementId, dataPos, size = _ebmlElement(buf, pos)
            if elementId == _MKV_CRC32 and size == 4:
                crcPos = dataPos
            elif elementId == _MKV_TRACKENTRY:
                codecId = b''
                private = None
                entryPos = dataPos
                while entryPos < dataPos + size:
                    childId, childData, childSize = _ebmlElement(buf, entryPos)
                    if childId == _MKV_CODECID:
                        codecId = bytes(buf[childData:childData + childSize])
                    elif childId == _MKV_CODECPRIVATE:
                        private = (entryPos, childData, childSize)
                    entryPos = childData + childSize
                if codecId.rstrip(b'\x00') == b'V_MPEG4/ISO/AVC' and private:
                    elementPos, privateData, privateSize = private
                    newData = _dedupeAvcC(buf[privateData:privateData + privateSize])
                    if newData is not None:
                        sizeLen = privateData - elementPos - 2
                        total = privateData + privateSize - elementPos
                        block = bytearray(b'\x63\xa2') + _ebmlSizeField(len(newData), sizeLen) + newData
                        free = total - len(block)
                        voidLen = 1
                        while voidLen < 8 and free - 1 - voidLen >= (1 << (7 * voidLen)) - 1:
                            voidLen += 1
                        if len(newData) >= (1 << (7 * sizeLen)) - 1 or free - 1 - voidLen < 0:
                            printDBG('fixMkvH264Header: no room for the Void element in %s' % filePath)
                        else:
                            block += bytearray((_MKV_VOID,)) + _ebmlSizeField(free - 1 - voidLen, voidLen) + bytearray(free - 1 - voidLen)
                            buf[elementPos:elementPos + total] = block
                            changed = True
            pos = dataPos + size
        if not changed:
            return False
        if crcPos is not None:
            buf[crcPos:crcPos + 4] = bytearray(struct.pack('<I', zlib.crc32(bytes(buf[crcPos + 4:tracksEnd])) & 0xFFFFFFFF))
        with open(path, 'r+b') as f:
            f.seek(tracksPos)
            f.write(bytes(buf[tracksPos:tracksEnd]))
        printDBG('fixMkvH264Header: SPS / PPS duplicates removed from the H.264 header of %s' % filePath)
        return True
    except Exception:
        printExc()
        return False


def fixMkvH264HeaderWhenDone(filePath, quietSecs=3, maxSecs=60):
    # A live recording stopped in the download manager: ffmpeg still writes the end of its MKV after that, the H.264
    # header included (box test 21.11.2026: a fix right away was gone again). The fix runs once the file has not
    # changed for quietSecs, in a thread of its own (only file access there).
    def _wait():
        try:
            path = fsPath(filePath)
            last = None
            quietSince = time.time()
            end = time.time() + maxSecs
            while time.time() < end:
                try:
                    st = os.stat(path)
                    state = (st.st_size, st.st_mtime)
                except OSError:
                    return
                if state != last:
                    last = state
                    quietSince = time.time()
                elif time.time() - quietSince >= quietSecs:
                    fixMkvH264Header(filePath)
                    return
                time.sleep(0.5)
            printDBG('fixMkvH264HeaderWhenDone: %s still changing after %d s, left as it is' % (filePath, maxSecs))
        except Exception:
            printExc()
    worker = threading.Thread(target=_wait, name='fixMkvH264Header')
    worker.daemon = True
    worker.start()
    return worker


def ensureText(data, encoding='utf-8'):
    if data is None:
        return u''

    if isinstance(data, text_type):
        return data

    if isinstance(data, binary_type):
        try:
            return data.decode(encoding)
        except Exception:
            try:
                return data.decode(encoding, 'replace')
            except Exception:
                try:
                    return data.decode('latin-1', 'replace')
                except Exception:
                    return u''

    try:
        return text_type(data)
    except Exception:
        try:
            return text_type(str(data))
        except Exception:
            return u''


def fsPath(path):
    path = ensureText(path)
    try:
        if text_type is not str:
            return path.encode('utf-8')
    except Exception:
        pass
    return path


def executeConsoleCmd(console, cmd):
    # start a command line on an eConsoleAppContainer, niced
    if hasattr(console, "setNice"):
        console.setNice(GetNice() + 2)
        console.execute(cmd)
    else:
        console.execute(E2PrioFix(cmd))


def terminateToolsOfFile(filePath, tools=('hlsdl', 'wget', 'curl', 'ffmpeg')):
    # Safety net for "Stop downloading". The download commands end in a redirect, so the console
    # runs them through a shell and its sendCtrlC() only reaches that shell: hlsdl / wget / curl /
    # ffmpeg can keep running and writing the file after the item shows "interrupted". So look
    # for the tool by its command line - it names the output file - and end it directly.
    killed = []
    try:
        needle = fsPath(filePath)
        if not isinstance(needle, binary_type):
            needle = needle.encode('utf-8', 'replace')
        toolNames = [t if isinstance(t, binary_type) else t.encode('utf-8') for t in tools]
        if not needle:
            return killed
        myPid = os.getpid()
        for entry in os.listdir('/proc'):
            if not entry.isdigit() or int(entry) == myPid:
                continue
            try:
                with open('/proc/%s/cmdline' % entry, 'rb') as f:
                    cmdline = f.read()
            except Exception:
                continue  # gone already, or not readable
            if needle in cmdline and any(name in cmdline for name in toolNames):
                try:
                    os.kill(int(entry), signal.SIGTERM)
                    killed.append(int(entry))
                except Exception:
                    pass
    except Exception:
        printExc()
    if killed:
        printDBG("terminateToolsOfFile ended pids %r for [%s]" % (killed, filePath))
    return killed


def shellQuote(value):
    value = ensureText(value)
    value = value.replace('\\', '\\\\')
    value = value.replace('"', '\\"')
    value = value.replace('`', '\\`')
    value = value.replace('$', '\\$')
    return value


def shellSingleQuote(value):
    # the whole value as one '...' shell word - nothing inside is interpreted by the shell
    return "'" + ensureText(value).replace("'", "'\\''") + "'"


def writeUtf8TextFile(path, data):
    try:
        txt = ensureText(data)
        f = open(fsPath(path), 'wb')
        try:
            f.write(txt.encode('utf-8'))
        finally:
            f.close()
        return True
    except Exception:
        printExc()
        return False


def readUtf8TextFile(path):
    try:
        f = open(fsPath(path), 'rb')
        try:
            data = f.read()
        finally:
            f.close()
        return ensureText(data)
    except Exception:
        return None


def filesAreIdentical(pathA, pathB):
    try:
        pathA = fsPath(pathA)
        pathB = fsPath(pathB)
        if not os.path.isfile(pathA) or not os.path.isfile(pathB):
            return False
        if os.path.getsize(pathA) != os.path.getsize(pathB):
            return False
        fa = open(pathA, 'rb')
        try:
            fb = open(pathB, 'rb')
            try:
                while True:
                    chunkA = fa.read(65536)
                    chunkB = fb.read(65536)
                    if chunkA != chunkB:
                        return False
                    if not chunkA:
                        return True
            finally:
                fb.close()
        finally:
            fa.close()
    except Exception:
        return False


# the extensions of the subtitles saved next to a download (the download manager removes / renames them with it)
SUBTITLE_SIDECAR_EXT = ('srt', 'ass')


def subtitleSidecarFiles(basePath):
    # the subtitle files saved next to the download basePath (without extension): name.srt, name.2.srt, name.de.srt,
    # name.de.2.srt - not "name.2023.srt" or "name.HD.srt" of another video
    import re
    found = []
    try:
        folder, name = os.path.split(ensureText(basePath))
        pattern = re.compile(r'^%s(?:\.[a-z]{2})?(?:\.(?:[2-9]|[1-9]\d))?\.(?:%s)$' % (re.escape(name), '|'.join(SUBTITLE_SIDECAR_EXT)))
        for entry in os.listdir(fsPath(folder or '.')):
            entry = ensureText(entry)
            if pattern.match(entry):
                found.append(os.path.join(folder, entry))
    except Exception:
        printExc()
    return sorted(found)


def safeRemoveFile(path):
    try:
        path = fsPath(path)
        if os.path.isfile(path):
            os.remove(path)
    except Exception:
        printExc()


class SidecarMixin(object):
    """
    Shared .txt / .jpg sidecar handling plus the generic "finish download"
    flow, used identically by WgetDownloader, HLSDownloader and
    MergeDownloader.

    The including class must also inherit from BaseDownloader (for
    self.filePath, self.onFinish()) and must implement self._cleanUp()
    itself, since temp-file cleanup differs per downloader.

    Usage in each downloader's __init__:
        self._initSidecarState()

    Usage in each downloader's _terminate():
        self._terminateSidecar()
    """

    def _initSidecarState(self):
        self.sidecarConsole = None
        self.sidecarConsole_appClosed_conn = None
        self.sidecarConsole_stderrAvail_conn = None
        self.sidecarEnabled = False
        self.sidecarTxt = ''
        self.sidecarImg = ''
        self.waitingForSidecar = False
        self.sidecarImgTmpPath = ''
        self.sidecarMetaLock = threading.Lock()
        self.sidecarMetaState = {}

    def _clearSidecarData(self):
        self.sidecarEnabled = False
        self.sidecarTxt = ''
        self.sidecarImg = ''
        self.waitingForSidecar = False
        self.sidecarMetaState = {}

    def _prepareSidecarData(self, meta):
        self._clearSidecarData()
        try:
            if meta.get('e2i_sidecar_enabled', False):
                self.sidecarEnabled = True
                self.sidecarTxt = meta.get('e2i_sidecar_txt', '')
                self.sidecarImg = meta.get('e2i_sidecar_img', '')
                printDBG("%s sidecar enabled" % self.__class__.__name__)
                self._startSidecarMetaLookup(meta.get('e2i_sidecar_meta'))
        except Exception:
            printExc()

    def _startSidecarMetaLookup(self, query):
        # e2i_sidecar_meta (urlmetahelper.sidecarMetaQuery): the moviemeta details (rating, genres, cast, plot,
        # poster) are looked up now, in a thread while the file downloads - not when the links are listed, so
        # playing costs no lookup. _writeTxtSidecar() takes the answer; one that comes after the download is done
        # rewrites the .txt itself. Each download gets its own state dict (a restart starts a new one).
        if not isinstance(query, dict) or not query:
            return
        state = {'result': None, 'txtPath': ''}
        self.sidecarMetaState = state
        siteTxt, siteImg, name, lock = self.sidecarTxt, self.sidecarImg, self.__class__.__name__, self.sidecarMetaLock

        def sidecarMetaLookup():
            from Plugins.Extensions.IPTVPlayer.libs.urlmetahelper import lookupSidecarMeta
            result = lookupSidecarMeta(query, siteTxt, siteImg)
            with lock:
                state['result'] = result
                txtPath = state['txtPath']
            if txtPath and result[0] and result[0] != siteTxt:
                # the download finished first: its .txt has the site text only
                if writeUtf8TextFile(txtPath, ensureText(result[0])):
                    printDBG("%s sidecar TXT rewritten with the moviemeta details [%s]" % (name, txtPath))

        printDBG("%s sidecar moviemeta lookup %r" % (name, query))
        # an E2iPlayer work thread (asynccall): pCommon's pycurl requests need its kill state, a plain thread's fail
        from Plugins.Extensions.IPTVPlayer.components.asynccall import AsyncMethod
        AsyncMethod(sidecarMetaLookup)()

    def _takeSidecarMetaResult(self, txtPath):
        # the moviemeta answer when it is there; else txtPath is noted for the thread's own rewrite
        state = self.sidecarMetaState
        if not state:
            return
        with self.sidecarMetaLock:
            result = state.get('result')
            if result is None:
                state['txtPath'] = txtPath
        if result is None:
            printDBG("%s sidecar moviemeta lookup still running, site text first" % self.__class__.__name__)
        else:
            self.sidecarTxt, self.sidecarImg = result

    def _writeTxtSidecar(self, filePath):
        try:
            self._takeSidecarMetaResult(ensureText(filePath).rsplit('.', 1)[0] + '.txt')
            if not self.sidecarTxt:
                printDBG("%s sidecar TXT skipped: empty content" % self.__class__.__name__)
                return

            basePath = ensureText(filePath).rsplit('.', 1)[0]
            txtPath = basePath + '.txt'
            newContent = ensureText(self.sidecarTxt)

            if os.path.isfile(fsPath(txtPath)):
                if readUtf8TextFile(txtPath) == newContent:
                    printDBG("%s sidecar TXT unchanged, skipping rewrite [%s]" % (self.__class__.__name__, txtPath))
                    return
                printDBG("%s sidecar TXT content changed, rewriting [%s]" % (self.__class__.__name__, txtPath))

            if writeUtf8TextFile(txtPath, newContent):
                printDBG("%s sidecar TXT saved [%s]" % (self.__class__.__name__, txtPath))
            else:
                printDBG("%s sidecar TXT save failed [%s]" % (self.__class__.__name__, txtPath))
        except Exception:
            printExc("%s sidecar TXT save failed" % self.__class__.__name__)

    def _imgSidecarDataAvail(self, data):
        return

    def _imgSidecarFinished(self, jpgPath, code):
        printDBG("%s._imgSidecarFinished code[%r]" % (self.__class__.__name__, code))

        # break circular references
        self.sidecarConsole_appClosed_conn = None
        self.sidecarConsole_stderrAvail_conn = None
        self.sidecarConsole = None
        tmpPath = self.sidecarImgTmpPath
        try:
            if code not in (0, None):
                # wget's exit code (1 generic, 4 network, 8 server error ...): what it left is a part of the
                # picture or an error page, not a poster
                printDBG("%s sidecar JPG download failed code[%r]" % (self.__class__.__name__, code))
                safeRemoveFile(tmpPath)
            elif os.path.isfile(fsPath(tmpPath)) and os.path.getsize(fsPath(tmpPath)) > 0 and self._startImgSidecarConversion(jpgPath, tmpPath):
                return  # ffmpeg makes a JPEG of it first, _imgSidecarConverted saves the picture then
        except Exception:
            printExc()
            self.sidecarConsole_appClosed_conn = None
            self.sidecarConsole = None
        self._saveImgSidecar(jpgPath, tmpPath)

    def _startImgSidecarConversion(self, jpgPath, tmpPath):
        # the picture as the server sent it: still gzip-encoded (some image CDNs compress unasked), or WebP / AVIF
        # under the .jpg name (the thumbnails of FYXXR and other sites) - the Enigma2 picture loader of VTi and
        # older images shows neither. gzip is undone here; WebP / AVIF go through ffmpeg (one frame as JPEG) in a
        # console run like the subtitle mux, which needs no open plugin window (convertWebp of the list icons needs
        # one for its ffmpeg fallback). True while ffmpeg runs. A conversion that fails keeps the file as it came.
        from Plugins.Extensions.IPTVPlayer.libs.pCommon import IsConvertibleImage, UngzipFile, common
        from Plugins.Extensions.IPTVPlayer.iptvdm.iptvdh import DMHelper
        from Plugins.Extensions.IPTVPlayer.tools.iptvtools import IsExecutable
        name = self.__class__.__name__
        path = fsPath(tmpPath)
        if UngzipFile(path):
            printDBG("%s sidecar JPG came gzip-encoded, decoded" % name)
        if not IsConvertibleImage(path):
            return False
        ffmpeg = DMHelper.GET_FFMPEG_PATH()
        if not IsExecutable(ffmpeg):
            # without ffmpeg only Pillow can read it (in place, here in the main thread: convertWebp's own
            # ffmpeg fallback does not run without the executable)
            printDBG("%s sidecar JPG is WebP/AVIF and there is no ffmpeg, trying Pillow" % name)
            common().convertWebp(path)
            if IsConvertibleImage(path):
                printDBG("%s sidecar JPG not converted, saved as it came" % name)
            return False
        convPath = tmpPath + '.jpg'
        safeRemoveFile(convPath)
        cmd = '%s -y -i "%s" -frames:v 1 -update 1 -q:v 2 "%s" > /dev/null 2>&1' % (ffmpeg, shellQuote(tmpPath), shellQuote(convPath))
        printDBG("%s sidecar JPG is WebP/AVIF, convert cmd[%s]" % (name, cmd))
        self.sidecarConsole = eConsoleAppContainer()
        self.sidecarConsole_appClosed_conn = eConnectCallback(self.sidecarConsole.appClosed, boundFunction(self._imgSidecarConverted, jpgPath, convPath))
        executeConsoleCmd(self.sidecarConsole, cmd)
        return True

    def _imgSidecarConverted(self, jpgPath, convPath, code):
        printDBG("%s._imgSidecarConverted code[%r]" % (self.__class__.__name__, code))
        self.sidecarConsole_appClosed_conn = None
        self.sidecarConsole = None
        tmpPath = self.sidecarImgTmpPath
        try:
            if code == 0 and os.path.isfile(fsPath(convPath)) and os.path.getsize(fsPath(convPath)) > 0:
                safeRemoveFile(tmpPath)
                os.rename(fsPath(convPath), fsPath(tmpPath))
                printDBG("%s sidecar JPG converted to JPEG" % self.__class__.__name__)
            else:
                printDBG("%s sidecar JPG conversion failed code[%r], the picture is saved as it came" % (self.__class__.__name__, code))
                safeRemoveFile(convPath)
        except Exception:
            printExc()
        self._saveImgSidecar(jpgPath, tmpPath)

    def _saveImgSidecar(self, jpgPath, tmpPath):
        self.waitingForSidecar = False
        self.sidecarImgTmpPath = ''
        try:
            if os.path.isfile(fsPath(tmpPath)) and os.path.getsize(fsPath(tmpPath)) > 0:
                if filesAreIdentical(tmpPath, jpgPath):
                    printDBG("%s sidecar JPG unchanged, discarding re-download [%s]" % (self.__class__.__name__, jpgPath))
                    safeRemoveFile(tmpPath)
                else:
                    safeRemoveFile(jpgPath)
                    os.rename(fsPath(tmpPath), fsPath(jpgPath))
                    try:
                        # wget gives the file the server's date (the poster's upload, years ago): the
                        # download's time instead, so the picture sorts next to its video
                        os.utime(fsPath(jpgPath), None)
                    except Exception:
                        printExc()
                    printDBG("%s sidecar JPG saved [%s]" % (self.__class__.__name__, jpgPath))
            else:
                printDBG("%s sidecar JPG failed [%s]" % (self.__class__.__name__, jpgPath))
                safeRemoveFile(tmpPath)
        except Exception:
            printExc()

        self._finishDownloadFlow()

    def _startImgSidecarDownload(self, filePath):
        try:
            if not self.sidecarImg:
                printDBG("%s sidecar JPG skipped: empty URL" % self.__class__.__name__)
                self._finishDownloadFlow()
                return

            basePath = ensureText(filePath).rsplit('.', 1)[0]
            jpgPath = basePath + '.jpg'
            tmpPath = jpgPath + '.new'
            self.sidecarImgTmpPath = tmpPath

            cmd = (config.plugins.iptvplayer.wgetpath.value or 'wget') + ' --header "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" --no-check-certificate "%s" -O "%s" > /dev/null 2>&1' % (shellQuote(self.sidecarImg), shellQuote(tmpPath))
            printDBG("%s sidecar JPG cmd[%s]" % (self.__class__.__name__, cmd))

            self.waitingForSidecar = True
            self.sidecarConsole = eConsoleAppContainer()
            self.sidecarConsole_appClosed_conn = eConnectCallback(self.sidecarConsole.appClosed, boundFunction(self._imgSidecarFinished, jpgPath))
            self.sidecarConsole_stderrAvail_conn = eConnectCallback(self.sidecarConsole.stderrAvail, self._imgSidecarDataAvail)
            if hasattr(self.sidecarConsole, "setNice"):
                self.sidecarConsole.setNice(GetNice() + 2)
                self.sidecarConsole.execute(cmd)
            else:
                self.sidecarConsole.execute(E2PrioFix(cmd))
        except Exception:
            printExc("%s sidecar JPG start failed" % self.__class__.__name__)
            self._finishDownloadFlow()

    def _terminateSidecar(self):
        # Call from each downloader's _terminate() to kill an in-flight
        # sidecar JPG download and avoid leaving a zombie process behind.
        if self.sidecarConsole is not None:
            try:
                if hasattr(self.sidecarConsole, "sendCtrlC"):
                    self.sidecarConsole.sendCtrlC()
                elif hasattr(self.sidecarConsole, "kill"):
                    self.sidecarConsole.kill()
            except Exception:
                printExc()
            self.sidecarConsole = None
            self.sidecarConsole_appClosed_conn = None
            self.sidecarConsole_stderrAvail_conn = None
            if self.sidecarImgTmpPath:
                # the Ctrl+C reaches the shell around wget / ffmpeg only; both name the temp file on their
                # command line (ffmpeg as its input)
                terminateToolsOfFile(self.sidecarImgTmpPath, ('wget', 'ffmpeg'))
                safeRemoveFile(self.sidecarImgTmpPath + '.jpg')
                safeRemoveFile(self.sidecarImgTmpPath)
                self.sidecarImgTmpPath = ''

    def _finishDownloadFlow(self):
        # Generic finish-flow used by all three downloaders. Relies on
        # self._cleanUp() being implemented by the downloader subclass
        # (temp-file cleanup differs per downloader).
        try:
            self.onFinish()
        except Exception:
            printExc()
        self._cleanUp()

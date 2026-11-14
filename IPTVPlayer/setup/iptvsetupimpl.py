# -*- coding: utf-8 -*-
#
# E2iPlayer setup: finds the external tools and installs the missing ones.
#   1. the image feed (opkg): one "opkg install" with the packages the feed offers
#   2. platform detection (bin/<platform>/platformtester)
#   3. every tool: present and usable -> registered, else downloaded from the binary feed of
#      this repository (feed/, GitHub Pages; armv7 and mipsel), checked against its SHA256SUMS,
#      started once and only then installed
#

###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc, GetBinDir, GetTmpDir, GetPyScriptCmd, IsFPUAvailable, ReadGnuMIPSABIFP, \
                                                          IsExecutable, Which, GetPluginDir
from Plugins.Extensions.IPTVPlayer.setup.iptvsetuphelper import CCmdValidator
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
###################################################

###################################################
# FOREIGN import
###################################################
from Screens.MessageBox import MessageBox
from Components.config import config, configfile
from Tools.BoundFunction import boundFunction
from Tools.Directories import resolveFilename, SCOPE_PLUGINS
from os import path as os_path, chmod as os_chmod, getpid as os_getpid
import hashlib
import re
import shutil
import sys
###################################################

# raise it when the setup has to run once more after an update (new tools, new feed files);
# runMain() starts the setup on its own when the saved value differs
SETUP_VERSION = '2026.11.13.2'

# binary feed of this repository (feed/, built and published by GitHub Actions);
# the hidden option binaryfeedurl overrides it for tests
FEED_URL = 'https://oe-mirrors.github.io/e2iplayer-zadmario/resources/'
FEED_PLATFORMS = ('armv7', 'mipsel')

PY3 = sys.version_info[0] >= 3
PY_VER = '%d.%d' % (sys.version_info[0], sys.version_info[1])
PY_PKG = 'python3' if PY3 else 'python'

# image feed packages, installed when the feed offers them and they are not installed yet
OPKG_PACKAGES = ['enigma2-plugin-extensions-e2iplayer-deps', 'duktape', 'quickjs', 'uchardet', 'rtmpdump', 'wget', 'curl', 'curl-impersonate',
                 'exteplayer3', 'gstplayer', 'unrar', 'unzip', 'ca-certificates', PY_PKG + '-pycurl']
# tools of OPKG_PACKAGES that may also be there without the package (copied by hand, own ipk, the
# binary feed): when one of these files exists, opkg is not asked - VTi lists curl-impersonate in its
# index but has no file for it ("not available from any configured src") and the user's own newer
# binary would be replaced otherwise
OPKG_TOOL_FILES = {'duktape': ['/usr/bin/duk'],
                   'quickjs': ['/usr/bin/qjs'],
                   'uchardet': ['/usr/bin/uchardet'],
                   'rtmpdump': ['/usr/bin/rtmpdump'],
                   'curl-impersonate': ['/usr/bin/curl-impersonate', '/usr/local/bin/curl-impersonate'],
                   'exteplayer3': ['/usr/bin/exteplayer3'],
                   'gstplayer': ['/usr/bin/gstplayer']}
# Pillow: the first one the feed offers
OPKG_PILLOW = ['python3-pillow'] if PY3 else ['python-pillow', 'python-imaging']

ST_FOUND = 'found'
ST_INSTALLED = 'installed'
ST_OLD = 'old'
ST_MISSING = 'missing'
ST_SKIPPED = 'skipped'
ST_NOT_RUNNING = 'not_running'
ST_DOWNLOAD_FAILED = 'download_failed'
ST_CHECKSUM = 'checksum'


def _fileSha256(filePath):
    h = hashlib.sha256()
    with open(filePath, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _uniquePaths(paths):
    ret = []
    for item in paths:
        item = (item or '').strip()
        if item and item not in ret:
            ret.append(item)
    return ret


def _version(pattern, data, conv=str):
    try:
        return conv(re.search(pattern, data).group(1))
    except Exception:
        return None


def _verTuple(text):
    # "0.10" -> (0, 10): compared part by part, not as a float (0.10 < 0.5 as a float)
    try:
        return tuple(int(part) for part in text.strip('.').split('.'))
    except Exception:
        return None


def _verAtLeast(found, minimum):
    found = _verTuple(found or '')
    return found is not None and found >= _verTuple(minimum)


def _lastOk(stsTab):
    # CCmdValidator result: the last command run was the accepted one
    return len(stsTab) > 0 and stsTab[-1] is True


class IPTVSetupImpl:
    def __init__(self, finished, showMessage, setInfo):
        printDBG("IPTVSetupImpl.__init__ -------------------------------")

        # callbacks
        self._finished = finished
        self._showMessage = showMessage
        self._setInfo = setInfo
        self.workingObj = None
        self.termination = False

        self.tmpDir = GetTmpDir()
        self.feedTmpDir = os_path.join(self.tmpDir, 'e2ifeed')

        self.gstreamerVersion = ""
        self.supportedPlatforms = ["sh4", "mipsel", "i686", "armv7", "armv5t"]
        self.platform = "unknown"

        self.opkgInstalled = []
        self.opkgToInstall = []
        self.feedBase = ''
        self.feedDownloaders = []
        self.feedDownloader = ''
        self.feedSums = {}
        self.feedError = ''

        self.tools = []
        self.toolIdx = 0
        self.currTool = None
        self.currUsable = ''
        self.detectResults = []
        self.results = []

        # minimum versions: what the plugin needs, for the tools of e2iplayer-deps the version of the
        # binary feed (an older one is offered as "deprecated", declining keeps it)
        self.wgetVersion = '1.19.2'
        self.uchardetVersion = '0.0.6'
        self.f4mdumpVersion = '0.82'
        self.hlsdlVersion = '0.38'
        self.cmdwrapVersion = '2'
        self.dukVersion = 6  # VER_FOR_IPTV of the iptvplayer patch
        self.subparserVersion = '0.9'
        self.gstplayerVersion = {'0.10': 20, '1.0': 10021}
        self.exteplayer3Version = 50

    def __del__(self):
        printDBG("IPTVSetupImpl.__del__ -------------------------------")

    def terminate(self):
        printDBG("IPTVSetupImpl.terminate -------------------------------")
        self.termination = True
        self._finished = None
        self._showMessage = None
        self._setInfo = None
        if self.workingObj:
            self.workingObj.terminate()

    def finish(self, *args):
        # also the callback of a MessageBox (its answer is not needed)
        printDBG("IPTVSetupImpl.finish")
        if self._finished:
            self._finished()

    def showMessage(self, message, type, callback):
        printDBG("IPTVSetupImpl.showMessage")
        if self._showMessage:
            self._showMessage(message, type, callback)

    def setInfo(self, title, message):
        printDBG("IPTVSetupImpl.setInfo")
        if self._setInfo:
            self._setInfo(title, message)

    def runCmds(self, cmdTabs, validator, callback):
        if self.termination:
            return
        self.workingObj = CCmdValidator(callback, validator, cmdTabs)
        self.workingObj.start()

    def start(self):
        printDBG("IPTVSetupImpl.start")
        self.opkgStep()

    ###################################################
    # STEP: IMAGE FEED (opkg)
    ###################################################
    def opkgStep(self):
        printDBG("IPTVSetupImpl.opkgStep")
        if not IsExecutable('opkg') or os_path.exists(GetPluginDir('plugin.pe2i')):
            self.platformDetect()
            return
        self.setInfo(_("Image feed"), _("Updating the package lists of the image feed..."))
        cmd = 'opkg update > /dev/null 2>&1; opkg list 2>/dev/null | cut -d " " -f 1; echo "@@INSTALLED@@"; opkg list-installed 2>/dev/null | cut -d " " -f 1'
        self.runCmds([cmd], lambda code, data: (True, False), self.opkgListFinished)

    def opkgListFinished(self, stsTab, dataTab):
        printDBG("IPTVSetupImpl.opkgListFinished")
        available, installed = set(), set()
        try:
            listed, inst = (dataTab[-1] + '\n@@INSTALLED@@').split('@@INSTALLED@@')[:2]
            available = {item.strip() for item in listed.split('\n') if item.strip()}
            installed = {item.strip() for item in inst.split('\n') if item.strip()}
        except Exception:
            printExc()

        packages = list(OPKG_PACKAGES)
        for item in OPKG_PILLOW:
            if item in available:
                packages.append(item)
                break
        toInstall = []
        for item in packages:
            if item not in available or item in installed:
                continue
            present = [path for path in OPKG_TOOL_FILES.get(item, []) if os_path.exists(path)]
            if present:
                printDBG("IPTVSetupImpl.opkgListFinished %s already there (%s), opkg not asked" % (item, present[0]))
                continue
            toInstall.append(item)
        printDBG("IPTVSetupImpl.opkgListFinished available %d, installed %d, to install %s" % (len(available), len(installed), toInstall))
        if not toInstall:
            self.platformDetect()
            return
        self.opkgToInstall = toInstall
        self.setInfo(_("Image feed"), _("Installing from the image feed:") + '\n' + ', '.join(toInstall))
        # the list of installed packages afterwards tells what really came (opkg's exit code is one for all)
        cmd = 'opkg install %s 2>&1; echo "@@INSTALLED@@"; opkg list-installed 2>/dev/null | cut -d " " -f 1' % ' '.join(toInstall)
        self.runCmds([cmd], lambda code, data: (True, False), self.opkgInstallFinished)

    def opkgInstallFinished(self, stsTab, dataTab):
        printDBG("IPTVSetupImpl.opkgInstallFinished sts[%r]" % stsTab)
        installed = set()
        try:
            installed = {item.strip() for item in (dataTab[-1] + '@@INSTALLED@@').split('@@INSTALLED@@')[1].split('\n') if item.strip()}
        except Exception:
            printExc()
        self.opkgInstalled = [item for item in self.opkgToInstall if item in installed]
        failed = [item for item in self.opkgToInstall if item not in installed]
        if failed:
            printDBG("IPTVSetupImpl.opkgInstallFinished not installed from the image feed: %s" % failed)
        self.platformDetect()

    ###################################################
    # STEP: PLATFORM DETECTION
    ###################################################
    def platformDetect(self):
        printDBG("IPTVSetupImpl.platformDetect")
        self.setInfo(_("Detection of the platform."), _("Plugin can be run on one of the following platforms: sh4, mipsel, i686, armv7, armv5t."))
        cmdTabs = []
        for platform in self.supportedPlatforms:
            platformtesterPath = resolveFilename(SCOPE_PLUGINS, "Extensions/IPTVPlayer/bin/%s/platformtester" % platform)
            try:
                os_chmod(platformtesterPath, 0o777)
            except Exception:
                printExc()
            cmdTabs.append(platformtesterPath + "  2>&1 ")

        def _platformValidator(code, data):
            if "Test platform OK" in data:
                return True, False
            else:
                return False, True
        self.runCmds(cmdTabs, _platformValidator, self.platformDetectFinished)

    def platformDetectFinished(self, stsTab, dataTab):
        printDBG("IPTVSetupImpl.platformDetectFinished")

        def _saveConfig(platform):
            self.platform = platform
            config.plugins.iptvplayer.plarform.value = self.platform
            printDBG("IPTVSetupImpl.platformDetectFinished platform[%s]" % self.platform)
            config.plugins.iptvplayer.plarform.save()
            configfile.save()

        if _lastOk(stsTab):
            _saveConfig(self.supportedPlatforms[len(stsTab) - 1])
            self.detectFPU()
        else:
            _saveConfig("unknown")
            self.showMessage(_("Fatal Error!\nPlugin is not supported with your platform."), MessageBox.TYPE_ERROR, boundFunction(self.finish, False))

    ###################################################
    # STEP: FPU DETECTION (mipsel)
    ###################################################
    def detectFPU(self):
        printDBG("IPTVSetupImpl.detectFPU")
        if self.platform == 'mipsel':
            hasAbiFlags, abiFP = ReadGnuMIPSABIFP('/lib/libc.so.6')
            if abiFP not in [-1, 0]:
                val = "soft_float" if abiFP == 3 else "hard_float"
                if config.plugins.iptvplayer.plarformfpuabi.value != val:
                    config.plugins.iptvplayer.plarformfpuabi.value = val
                    config.plugins.iptvplayer.plarformfpuabi.save()
                    configfile.save()
            printDBG(">> detectFPU hasAbiFlags[%s] abiFP[%s] -> [%s]" % (hasAbiFlags, abiFP, IsFPUAvailable()))
        self.getGstreamerVer()

    ###################################################
    # STEP: GSTREAMER VERSION
    ###################################################
    def getGstreamerVer(self):
        printDBG("IPTVSetupImpl.getGstreamerVer [%s]" % os_getpid())
        self.setInfo(_("Detection of the gstreamer version."), None)

        def _verValidator(code, data):
            if 'libgstbase-' in data:
                return True, False
            elif 'GStreamer Core Library version ' in data:
                return True, False
            else:
                return False, True
        verCmdTab = []
        verCmdTab.append('cat /proc/%s/maps | grep libgst' % os_getpid())
        verCmdTab.append('gst-launch-1.0 --gst-version')
        verCmdTab.append('gst-launch --gst-version')
        self.runCmds(verCmdTab, _verValidator, self.getGstreamerVerFinished)

    def getGstreamerVerFinished(self, stsTab, dataTab):
        printDBG("IPTVSetupImpl.getGstreamerVerFinished")
        self.gstreamerVersion = ""
        if _lastOk(stsTab):
            if 'libgstbase-1.0.so' in dataTab[-1] or ' version 1.' in dataTab[-1]:
                self.gstreamerVersion = "1.0"
            elif 'libgstbase-0.10.so' in dataTab[-1] or ' version 0.' in dataTab[-1]:
                self.gstreamerVersion = "0.10"
        self.feedStep()

    ###################################################
    # STEP: BINARY FEED (checksum list + a downloader that checks certificates)
    ###################################################
    def feedStep(self):
        printDBG("IPTVSetupImpl.feedStep")
        self.feedSums = {}
        if self.platform not in FEED_PLATFORMS:
            printDBG("IPTVSetupImpl.feedStep no binary feed for platform [%s]" % self.platform)
            self.toolsStart()
            return

        base = ''
        try:
            base = config.plugins.iptvplayer.binaryfeedurl.value.strip()
        except Exception:
            printExc()
        if not base:
            base = FEED_URL
        if not base.endswith('/'):
            base += '/'
        self.feedBase = base + 'bin/' + self.platform + '/'

        # GNU wget and curl check the certificate; busybox wget does not and is left out
        downloaders = []
        for wget in _uniquePaths([config.plugins.iptvplayer.wgetpath.value, '/usr/bin/fullwget', 'wget', '/usr/bin/wget']):
            downloaders.append('"%s" -V 2>&1 | grep -q "GNU Wget" && "%s" -q -T 30 -t 2 -O "%%(out)s" "%%(url)s"' % (wget, wget))
        downloaders.append('curl -f -s -S -L --connect-timeout 30 --retry 2 -o "%(out)s" "%(url)s"')
        python = Which('python3') if PY3 else (Which('python') or Which('python2.7'))
        if python:
            # urllib checks the certificate since Python 2.7.9
            downloaders.append('"%s" "%s" "%%(url)s" "%%(out)s"' % (python, GetPluginDir('iptvdm/pwget.py')))
        self.feedDownloaders = downloaders

        sumsFile = os_path.join(self.feedTmpDir, 'SHA256SUMS')
        cmdTabs = []
        for item in downloaders:
            cmdTabs.append('mkdir -p "%s"; rm -f "%s"; %s 2>&1' % (self.feedTmpDir, sumsFile, item % {'url': self.feedBase + 'SHA256SUMS', 'out': sumsFile}))
        self.setInfo(_("E2iPlayer binary feed"), _("Reading the list of tools of the binary feed..."))
        self.runCmds(cmdTabs, lambda code, data: (code == 0, code != 0), self.feedStepFinished)

    def feedStepFinished(self, stsTab, dataTab):
        printDBG("IPTVSetupImpl.feedStepFinished")
        if _lastOk(stsTab):
            try:
                with open(os_path.join(self.feedTmpDir, 'SHA256SUMS'), 'r') as f:
                    for line in f:
                        line = line.split()
                        if len(line) == 2 and len(line[0]) == 64:
                            self.feedSums[line[1].lstrip('*')] = line[0].lower()
            except Exception:
                printExc()
        if self.feedSums:
            self.feedDownloader = self.feedDownloaders[len(stsTab) - 1]
            printDBG("IPTVSetupImpl.feedStepFinished %d files, downloader [%s]" % (len(self.feedSums), self.feedDownloader))
            self.toolsStart()
        else:
            self.feedError = _("The E2iPlayer binary feed could not be read with a certificate check.\nPlease install the certificates and a downloader from the image feed:\nopkg install ca-certificates wget\nand start the setup again.")
            self.toolsStart()  # the summary at the end shows feedError

    ###################################################
    # STEP: TOOLS
    ###################################################
    def toolsStart(self, *args):
        self.tools = self.getToolSpecs()
        self.toolIdx = 0
        self.results = []
        self.toolStep()

    def getToolSpecs(self):
        def pluginBin(name):
            return resolveFilename(SCOPE_PLUGINS, 'Extensions/IPTVPlayer/bin/' + name)

        def fileExists(path):
            return '[ -f "%s" ] && echo "@@FILE@@"' % path

        opt = config.plugins.iptvplayer
        gst = self.gstreamerVersion

        def _wget(code, data):
            if 'BusyBox' in data or '+https' not in data:
                return False
            return _verAtLeast(_version(r"GNU Wget ([0-9]+\.[0-9]+(?:\.[0-9]+)?)", data), self.wgetVersion)

        def _minVer(pattern, minimum):
            def _check(code, data):
                return _verAtLeast(_version(pattern, data), minimum)
            return _check

        subparserVer = _minVer(r'^\s*([0-9]+(?:\.[0-9]+)*)', self.subparserVersion)

        def _gstplayer(code, data):
            ver = _version(r'"GSTPLAYER_EXTENDED":\{"version":([0-9]+)[^0-9]', data, int)
            if ver is None or (gst == '0.10' and ver >= 10000):
                return False
            return ver >= self.gstplayerVersion.get(gst, 0)

        def _curl(code, data):
            return code == 0 and re.search(r'(^|\n)curl [0-9]', data) is not None

        subparserPath = resolveFilename(SCOPE_PLUGINS, 'Extensions/IPTVPlayer/libs/iptvsubparser/_subparser.so')
        subparserCmd = GetPyScriptCmd('modver') + ' "%s" iptvsubparser _subparser 2>&1' % resolveFilename(SCOPE_PLUGINS, 'Extensions/IPTVPlayer/libs/')

        tools = [
            {'name': 'wget', 'file': 'wget', 'option': opt.wgetpath, 'install': '/usr/bin/fullwget',
             'paths': ['wget', '/usr/bin/wget', '/usr/bin/fullwget', GetBinDir('wget')],
             'detect': lambda p: '"%s" -V 2>&1' % p, 'valid': _wget,
             'usable': lambda code, data: 'BusyBox' not in data and '+https' in data,
             'desc': _('The "%s" utility is used by the %s to buffering and downloading [%s] links.') % ('wget', 'E2iPlayer', 'http, https, f4m, uds, hls')},
            {'name': 'curl', 'file': 'curl', 'install': '/usr/bin/curl',
             'paths': ['/usr/bin/curl', 'curl'],
             'detect': lambda p: '"%s" --version 2>&1' % p,
             'valid': _curl},
            {'name': 'rtmpdump', 'file': 'rtmpdump', 'option': opt.rtmpdumppath, 'install': '/usr/bin/rtmpdump',
             'paths': ['/usr/bin/rtmpdump', 'rtmpdump'],
             'detect': lambda p: '"%s" --help 2>&1' % p,
             'valid': lambda code, data: re.search(r'RTMPDump v?2\.[4-9]', data) is not None,
             'desc': _('The "%s" utility is used by the %s to buffering and downloading [%s] links.') % ('rtmpdump', 'E2iPlayer', 'rtmp, rtmpt, rtmpe, rtmpte, rtmps')},
            {'name': 'uchardet', 'file': 'uchardet', 'option': opt.uchardetpath, 'install': '/usr/bin/uchardet',
             'paths': ['/usr/bin/uchardet', GetBinDir('uchardet')],
             'detect': lambda p: '"%s" --version 2>&1' % p, 'valid': _minVer(r"Version\s([0-9]+\.[0-9]+\.[0-9]+)", self.uchardetVersion),
             'usable': lambda code, data: 'Version' in data,
             'desc': _('The "%s" utility is used by the %s to determine the encoding of the text.') % ('uchardet', 'E2iPlayer')},
            {'name': _("C subtitle parser"), 'file': '_subparser.so_py' + PY_VER, 'install': subparserPath, 'test': False,
             'paths': [subparserPath],
             'detect': lambda p: subparserCmd,
             'valid': lambda code, data: code == 0 and subparserVer(code, data),
             'usable': lambda code, data: code == 0 and _verTuple(_version(r'^\s*([0-9.]+)', data) or '') is not None,
             'desc': _('It improves subtitles parsing.\n').strip()},
            {'name': 'hlsdl', 'file': 'hlsdl', 'option': opt.hlsdlpath, 'install': pluginBin('hlsdl'),
             'paths': [pluginBin('hlsdl'), '/usr/bin/hlsdl'],
             'detect': lambda p: '"%s" 2>&1' % p, 'valid': _minVer(r"hlsdl v([0-9.]+?)[^0-9.]", self.hlsdlVersion),
             'usable': lambda code, data: 'hlsdl v' in data,
             'desc': _('It improves HLS/M3U8 stream download.\n').strip()},
            {'name': 'cmdwrap', 'file': 'cmdwrap', 'option': opt.cmdwrappath, 'install': pluginBin('cmdwrap'),
             'paths': [pluginBin('cmdwrap'), '/usr/bin/cmdwrap'],
             'detect': lambda p: '"%s" 2>&1' % p, 'valid': _minVer(r"Version\:\s*([0-9.]+?)[^0-9.]", self.cmdwrapVersion),
             'usable': lambda code, data: 'cmdwrap input_file' in data,
             'desc': _('It improves commands execution with very long arguments.\n').strip()},
            {'name': 'duk', 'file': 'duk', 'option': opt.dukpath, 'install': pluginBin('duk'),
             'paths': [pluginBin('duk'), '/usr/bin/duk'],
             'detect': lambda p: '"%s" --help 2>&1' % p,
             'valid': lambda code, data: 'restrict-memory' in data and (_version(r'VER_FOR_IPTV:\s([0-9]+)', data, int) or 0) >= self.dukVersion,
             'usable': lambda code, data: 'restrict-memory' in data,
             'desc': _('Duktape is an embeddable Javascript engine, with a focus on portability and compact footprint.\n').strip()},
            {'name': 'qjs', 'file': 'qjs', 'option': opt.qjspath, 'install': '/usr/bin/qjs',
             'paths': [opt.qjspath.value, '/usr/bin/qjs', 'qjs'],
             'detect': lambda p: '"%s" -e "print(\'@@QJS@@\')" 2>&1' % p,
             'valid': lambda code, data: '@@QJS@@' in data},
            {'name': 'f4mdump', 'file': 'f4mdump', 'option': opt.f4mdumppath, 'install': '/usr/bin/f4mdump',
             'paths': ['/usr/bin/f4mdump', GetBinDir('f4mdump')],
             'detect': lambda p: '"%s" 2>&1' % p, 'valid': _minVer(r"F4MDump v([0-9.]+?)[^0-9.]", self.f4mdumpVersion),
             'usable': lambda code, data: 'F4MDump v' in data,
             'desc': _('The "%s" utility is used by the %s to buffering and downloading [%s] links.') % ('f4mdump', 'E2iPlayer', 'f4m, uds')},
            {'name': 'e2ipow', 'file': 'e2ipow', 'install': '/usr/bin/e2ipow',
             'paths': ['/usr/bin/e2ipow', 'e2ipow'],
             'detect': lambda p: '"%s" --version 2>&1' % p,
             'valid': lambda code, data: re.search(r'(^|\n)e2ipow [0-9]', data) is not None},
            # local media and the folder browser; lists to stderr: "<name>//d//..."
            {'name': 'lsdir', 'file': 'lsdir', 'option': opt.lsdirpath, 'install': '/usr/bin/lsdir',
             'paths': ['/usr/bin/lsdir', GetBinDir('lsdir')],
             'detect': lambda p: '"%s" "/" dl d 2>&1' % p,
             'valid': lambda code, data: '//d//' in data},
            # the upstream build needs a recent glibc (crashes on VTi 15): the start test keeps it out there
            {'name': 'curl-impersonate', 'file': 'curl-impersonate', 'option': opt.curlimpersonatepath, 'install': '/usr/bin/curl-impersonate',
             'paths': [opt.curlimpersonatepath.value, '/usr/bin/curl-impersonate', '/usr/local/bin/curl-impersonate'],
             'detect': lambda p: '"%s" --version 2>&1' % p,
             'valid': _curl},
            {'name': 'exteplayer3', 'option': opt.exteplayer3path,
             'paths': ['/usr/bin/exteplayer3', GetBinDir('exteplayer3')],
             'detect': lambda p: '"%s" 2>&1' % p,
             'valid': lambda code, data: (_version(r'"EPLAYER3_EXTENDED":\{"version":([0-9]+)[^0-9]', data, int) or 0) >= self.exteplayer3Version,
             'usable': lambda code, data: '"EPLAYER3_EXTENDED"' in data,
             'desc': _('The "%s" utility is used by the %s as external movie player based on the ffmpeg and libeplayer.') % ('exteplayer3', 'E2iPlayer')},
            # PNG plugin for graphic subtitles, exteplayer3 dlopen()s it by name - only when the image has none
            {'name': 'exteplayer3png.so', 'file': 'exteplayer3png.so', 'install': '/usr/lib/exteplayer3png.so', 'test': False,
             'paths': ['/usr/lib/exteplayer3png.so'],
             'detect': fileExists, 'valid': lambda code, data: '@@FILE@@' in data,
             'when': lambda: IsExecutable(opt.exteplayer3path.value)},
            {'name': 'gstplayer', 'option': opt.gstplayerpath,
             'paths': ['/usr/bin/gstplayer', GetBinDir('gstplayer')],
             'detect': lambda p: '"%s" 2>&1' % p, 'valid': _gstplayer,
             'usable': lambda code, data: '"GSTPLAYER_EXTENDED"' in data,
             'when': lambda: gst != '',
             'desc': _('The "%s" utility is used by the %s as external movie player.') % ('gstplayer', 'E2iPlayer')},
            # gst-ifdsrc (buffering with gstplayer) - only when the image has none
            {'name': 'gst-ifdsrc', 'file': 'libgstifdsrc.so', 'install': '/usr/lib/gstreamer-1.0/libgstifdsrc.so', 'test': False,
             'paths': ['/usr/lib/gstreamer-1.0/libgstifdsrc.so'],
             'detect': fileExists, 'valid': lambda code, data: '@@FILE@@' in data,
             'when': lambda: gst == '1.0' and IsExecutable(opt.gstplayerpath.value),
             'desc': _('It improves buffering mode with the gstplayer.\n').strip()},
        ]
        for spec in tools:
            spec['paths'] = _uniquePaths(spec['paths'])
        return tools

    def toolStep(self):
        while self.toolIdx < len(self.tools):
            spec = self.tools[self.toolIdx]
            if spec.get('when') is None or spec['when']():
                break
            self.toolIdx += 1
        else:
            self.showSummary()
            return

        printDBG("IPTVSetupImpl.toolStep [%s]" % spec['name'])
        self.currTool = spec
        self.currUsable = ''
        self.detectResults = []
        self.setInfo(_('Detection of the "%s" utility.') % spec['name'], spec.get('desc', _('The "%s" utility is used by IPTVPlayer.') % spec['name']))

        def _validator(code, data):
            self.detectResults.append((code, data))
            ok = spec['valid'](code, data)
            return ok, not ok
        self.runCmds([spec['detect'](path) for path in spec['paths']], _validator, self.toolDetectFinished)

    def toolDetectFinished(self, stsTab, dataTab):
        spec = self.currTool
        if _lastOk(stsTab):
            self.toolDone(spec['paths'][len(stsTab) - 1], ST_FOUND)
            return

        usableCheck = spec.get('usable')
        if usableCheck:
            for idx in range(len(self.detectResults)):
                code, data = self.detectResults[idx]
                if usableCheck(code, data):
                    self.currUsable = spec['paths'][idx]
                    break

        if spec.get('file') and spec['file'] in self.feedSums:
            # ask as the old setup did (same, already translated texts); the summary follows at the end
            if self.currUsable:
                message = _('Utility "%s" is deprecated. \nDo you want to install new one?') % spec['name']
            else:
                message = _('Utility "%s" has not been detected. \nDo you want to install it?') % spec['name']
            if spec.get('desc'):
                message += '\n\n' + spec['desc']
            self.showMessage(message, MessageBox.TYPE_YESNO, self.toolDownloadAnswer)
        else:
            self.toolDone(self.currUsable, ST_OLD if self.currUsable else ST_MISSING)

    def toolDownloadAnswer(self, ret=None):
        if ret:
            self.toolDownload()
        else:
            self.toolDone(self.currUsable, ST_OLD if self.currUsable else ST_SKIPPED)

    def toolDownload(self):
        spec = self.currTool
        tmpFile = os_path.join(self.feedTmpDir, spec['file'])
        cmd = 'mkdir -p "%s"; rm -f "%s"; %s 2>&1' % (self.feedTmpDir, tmpFile, self.feedDownloader % {'url': self.feedBase + spec['file'], 'out': tmpFile})
        self.setInfo(_('Downloading "%s".') % spec['name'], _("E2iPlayer binary feed"))
        self.runCmds([cmd], lambda code, data: (code == 0, False), self.toolDownloadFinished)

    def toolDownloadFinished(self, stsTab, dataTab):
        spec = self.currTool
        if not _lastOk(stsTab):
            self.toolDone(self.currUsable, ST_DOWNLOAD_FAILED)
            return
        tmpFile = os_path.join(self.feedTmpDir, spec['file'])
        try:
            sha = _fileSha256(tmpFile)
        except Exception:
            printExc()
            sha = ''
        if sha != self.feedSums[spec['file']]:
            printDBG("IPTVSetupImpl.toolDownloadFinished checksum error [%s] [%s] != [%s]" % (spec['file'], sha, self.feedSums[spec['file']]))
            self.toolDone(self.currUsable, ST_CHECKSUM)
            return

        # copied next to the target, started there and moved over the old file only when it runs
        target = spec['install']
        newFile = target + '.e2inew'
        cmd = 'mkdir -p "%s" && cp -f "%s" "%s" && chmod 755 "%s"' % (os_path.dirname(target), tmpFile, newFile, newFile)
        test = spec.get('test', True)
        if test:
            cmd += ' && ' + spec['detect'](newFile)
        self.setInfo(_('Installing "%s".') % spec['name'], None)

        def _validator(code, data):
            if test:
                ok = spec['valid'](code, data)
            else:
                ok = code == 0
            return ok, False
        self.runCmds([cmd], _validator, self.toolInstallFinished)

    def toolInstallFinished(self, stsTab, dataTab):
        spec = self.currTool
        target = spec['install']
        newFile = target + '.e2inew'
        if _lastOk(stsTab):
            cmd = 'mv -f "%s" "%s"' % (newFile, target)
            self.runCmds([cmd], lambda code, data: (code == 0, False), self.toolMoveFinished)
        else:
            printDBG("IPTVSetupImpl.toolInstallFinished [%s] does not run: %r" % (spec['name'], dataTab))
            self.runCmds(['rm -f "%s"' % newFile], lambda code, data: (True, False), lambda *args: self.toolDone(self.currUsable, ST_NOT_RUNNING))

    def toolMoveFinished(self, stsTab, dataTab):
        if _lastOk(stsTab):
            self.toolDone(self.currTool['install'], ST_INSTALLED)
        else:
            self.toolDone(self.currUsable, ST_NOT_RUNNING)

    def toolDone(self, path, status):
        spec = self.currTool
        printDBG("IPTVSetupImpl.toolDone [%s] status[%s] path[%s]" % (spec['name'], status, path))
        option = spec.get('option')
        if option is not None and option.value != path:
            option.value = path
            option.save()
            configfile.save()
        self.results.append((spec['name'], status, path))
        self.toolIdx += 1
        self.toolStep()

    ###################################################
    # SUMMARY
    ###################################################
    def showSummary(self):
        printDBG("IPTVSetupImpl.showSummary %r" % self.results)
        try:
            config.plugins.iptvplayer.setupversion.value = SETUP_VERSION
            config.plugins.iptvplayer.setupversion.save()
            configfile.save()
        except Exception:
            printExc()
        # the downloads are installed (or rejected) by now
        try:
            shutil.rmtree(self.feedTmpDir)
        except Exception:
            pass
        # the system page probed the tools before the setup ran: probe them again
        try:
            from Plugins.Extensions.IPTVPlayer.components.iptvplayerinfoview import ResetSystemProbe
            ResetSystemProbe()
        except Exception:
            printExc()

        texts = {ST_INSTALLED: _("installed from the E2iPlayer binary feed"),
                 ST_OLD: _("old version kept"),
                 ST_MISSING: _("not installed"),
                 ST_SKIPPED: _("not installed (declined)"),
                 ST_NOT_RUNNING: _("does not run on this image"),
                 ST_DOWNLOAD_FAILED: _("download failed"),
                 ST_CHECKSUM: _("checksum error")}
        lines = []
        if self.opkgInstalled:
            lines.append(_("Installing from the image feed:") + ' ' + ', '.join(self.opkgInstalled))
        if self.feedError:
            lines.append(self.feedError)
        for name, status, _path in self.results:
            if status == ST_FOUND:
                continue
            lines.append('%s: %s' % (name, texts.get(status, status)))
        # a Python extension cannot be replaced in the running Enigma2: the old one stays loaded until a restart
        if any(status == ST_INSTALLED and path.endswith('_subparser.so') for name, status, path in self.results):
            lines.append(_("Restart Enigma2 (GUI) to load the new subtitles parser."))
        if not lines:
            self.finish()
            return
        self.setInfo(_("Information"), None)
        self.showMessage('\n'.join(lines), MessageBox.TYPE_INFO, self.finish)

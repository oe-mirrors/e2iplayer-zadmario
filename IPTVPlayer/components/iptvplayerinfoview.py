# -*- coding: utf-8 -*-
#
#  E2iPlayer info / diagnostics screen.
#
#  Opened from the BLUE menu -> "Info" and with INFO / EPG / HELP in the
#  host selection and the settings. Three pages, switched with LEFT / RIGHT:
#
#    About   - version, project links, credits
#    System  - E2iPlayer / Python / image / box / CPU / RAM / clock / IPv6,
#              every external tool (at the path the plugin runs it from) and
#              Python module with its version (or what does not work without
#              it), free space of the config, temp, download and buffering
#              folders, the debug-log setting
#    Log     - a live tail of the E2iPlayer debug log (if enabled)
#
#  GREEN  saves the current page to /tmp (sysinfo.txt or debug.txt).
#  YELLOW toggles the live refresh on the Log page.
#  BLUE   clears the debug log (Log page only).
#
#  LogSystemInfoAtStartup() is called from plugin start: it runs the probe
#  once and writes the full snapshot (incl. binary versions) near the top
#  of the debug log, so it is already in any log a user shares for
#  support. The screen reuses that cached result.
#
#  Like the on-screen keyboard: real pixels per resolution, every picture
#  in its real size, no colour markup in texts - older images (VTi) can't
#  scale at runtime and don't all render "\c" escapes.
#
import os
import sys
import time

from enigma import eTimer, eListboxPythonMultiContent, gFont, RT_HALIGN_LEFT, RT_VALIGN_CENTER
from Components.ActionMap import ActionMap
from Components.config import config
from Components.Label import Label
from Components.ScrollLabel import ScrollLabel
from Screens.Screen import Screen
from Components.Pixmap import Pixmap

###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.components.iptvlist import IPTVListComponentBase
from Plugins.Extensions.IPTVPlayer.components.e2ivk import GetVKTier, _s, toNative, colorKeySkin
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import (
    printDBG, printExc, iptv_system, eConnectCallback, formatBytes, GetImageName,
    GetIPTVPlayerVersion, GetIPTVPlayerComitStamp, GetShortPythonVersion,
    GetConfigDir, GetTmpDir, GetDebugLogPath, GetFFmpegPath, GetQjsPath, GetBinDir, GetPluginDir,
    IsExecutable, Which, defaultToolPath,
)
###################################################

SYSINFO_FILE = "/tmp/e2iplayer_sysinfo.txt"
DEBUGCOPY_FILE = "/tmp/e2iplayer_debug.txt"

# shown on the Log page; the saved copy takes 8 times as much. Smaller than
# on python3: the whole text is laid out again on every refresh, which is
# slow on older boxes
LOG_TAIL_BYTES = 32 * 1024
LOG_REFRESH_MS = 2000

PAGE_ABOUT, PAGE_SYSTEM, PAGE_LOG = 0, 1, 2
# lambdas: translated when shown, not at import (language change without restart)
PAGE_NAMES = {PAGE_ABOUT: lambda: _("About"), PAGE_SYSTEM: lambda: _("System"), PAGE_LOG: lambda: _("Log")}

_HEADING_COLOR = 0x66ccff   # System page headings, same accent blue as the articles
_TEXT_COLOR = 0xffffff

# One shell script that probes every external binary at once, so the
# System page needs a single non-blocking iptv_system() call. It is
# written to a temp file and run as `sh <file>` - otherwise iptv_system
# logs the whole ~1 KB command three times per run into the debug log.
# stdin from /dev/null (exteplayer3/gstplayer read commands from stdin
# and would otherwise block); `timeout` guards the rest if it exists -
# BusyBox before 1.30 (VTi) only knows `timeout -t SECS`, so the working
# syntax is tried first.
# duktape's `duk` has no --version flag, so run a one-line script that
# prints Duktape.version (e.g. 20700 -> shown as 2.7.0). quickjs' `qjs
# --version` prints the bare version (e.g. 0.16.2).
# Every tool is probed at the path the plugin runs it from (the shell
# variables of _probeToolPaths()) and only when it is there; every section
# ends with that path ("-" = missing). unzip / unrar without arguments
# print their banner (unrar after an empty line), so the first non-empty
# line is taken.
_PROBE_SCRIPT_PATH = "/tmp/.e2i_sysprobe.sh"

_P = '</dev/null 2>&1'
_PROBE_SCRIPT = (
    'T=""; if timeout 4 true >/dev/null 2>&1; then T="timeout 4"; '
    'elif timeout -t 4 true >/dev/null 2>&1; then T="timeout -t 4"; fi; '
    'w(){ command -v "$1" 2>/dev/null || echo "-"; }; '
    'p(){ [ -n "$1" ] && [ -x "$1" ] && echo "$1" || echo "-"; }; '
    'echo "@@hlsdl";       [ -x "$HL" ] && ($T "$HL" %s || true) | head -n 2; p "$HL"; '
    'echo "@@cmdwrap";     [ -x "$CW" ] && ($T "$CW" %s || true) | head -n 1; p "$CW"; '
    'echo "@@lsdir";       [ -x "$LS" ] && ($T "$LS" --version %s || true) | head -n 1; p "$LS"; '
    'echo "@@f4mdump";     [ -x "$F4" ] && ($T "$F4" %s || true) | head -n 1; p "$F4"; '
    'echo "@@ffmpeg";      [ -x "$FF" ] && ($T "$FF" -version %s || true) | head -n 1; p "$FF"; '
    'echo "@@wget";        [ -x "$WG" ] && ($T "$WG" --version %s || true) | head -n 1; p "$WG"; '
    'echo "@@curl";        C=$(w curl); [ "$C" != "-" ] && ($T "$C" --version %s || true) | head -n 1; echo "$C"; '
    'echo "@@curlimp";     [ -x "$CI" ] && ($T "$CI" --version %s || true) | head -n 1; p "$CI"; '
    'echo "@@rtmpdump";    [ -x "$RT" ] && ($T "$RT" --help %s || true) | grep -i rtmpdump | head -n 1; p "$RT"; '
    'echo "@@exteplayer3"; [ -x "$EP" ] && ($T "$EP" %s || true) | head -n 2; p "$EP"; '
    'echo "@@gstplayer";   [ -x "$GP" ] && ($T "$GP" %s || true) | head -n 2; p "$GP"; '
    'echo "@@gstplayer2";  C=$(w gstplayer2); [ "$C" != "-" ] && ($T "$C" %s || true) | head -n 2; echo "$C"; '
    'echo "@@duktape";     D=/tmp/.e2i_dukver.js; '
    '  printf "%%s" \'try{var v=Duktape.version;print(Math.floor(v/10000)+"."+(Math.floor(v/100)%%100)+"."+(v%%100))}catch(e){print("?")}\' > $D; '
    '  [ -x "$DK" ] && ($T "$DK" $D %s || true) | head -n 1; rm -f $D; p "$DK"; '
    'echo "@@quickjs";     [ -x "$QJ" ] && ($T "$QJ" --version %s || true) | head -n 1; p "$QJ"; '
    'echo "@@uchardet";    [ -x "$UC" ] && ($T "$UC" --version %s || true) | grep -i "version" | head -n 1; p "$UC"; '
    'echo "@@unzip";       U=$(w unzip); [ "$U" != "-" ] && ($T unzip %s || true) | grep "[^[:space:]]" | head -n 1; echo "$U"; '
    'echo "@@unrar";       U=$(w unrar); [ "$U" != "-" ] && ($T unrar %s || true) | grep "[^[:space:]]" | head -n 1; echo "$U"; '
    'echo "@@deps";        (opkg list-installed 2>/dev/null | grep -i e2iplayer-deps || true); '
    'echo "@@ifdsrc";      (opkg list-installed 2>/dev/null | grep "^gst-ifdsrc " || true); '
    'echo "@@end"\n'
) % ((_P,) * 17)


def _pluginBin(name):
    # IPTVPlayer/bin/<name>: where the setup installs the tools it downloads
    return GetBinDir(name, '')


# key in the probe, shell variable, setup option, where the setup looks for it (in this order)
_SETUP_TOOLS = (
    ('hlsdl', 'HL', 'hlsdlpath', lambda: [_pluginBin('hlsdl'), '/usr/bin/hlsdl']),
    ('cmdwrap', 'CW', 'cmdwrappath', lambda: [_pluginBin('cmdwrap'), '/usr/bin/cmdwrap']),
    ('f4mdump', 'F4', 'f4mdumppath', lambda: ['/usr/bin/f4mdump', _pluginBin('f4mdump')]),
    ('wget', 'WG', 'wgetpath', lambda: ['wget', '/usr/bin/wget', '/usr/bin/fullwget', _pluginBin('wget')]),
    ('rtmpdump', 'RT', 'rtmpdumppath', lambda: ['/usr/bin/rtmpdump', 'rtmpdump']),
    ('duktape', 'DK', 'dukpath', lambda: [_pluginBin('duk'), '/usr/bin/duk']),
    ('uchardet', 'UC', 'uchardetpath', lambda: ['/usr/bin/uchardet', _pluginBin('uchardet')]),
    ('exteplayer3', 'EP', 'exteplayer3path', lambda: [defaultToolPath('exteplayer3')]),
    ('gstplayer', 'GP', 'gstplayerpath', lambda: ['/usr/bin/gstplayer', _pluginBin('gstplayer')]),
)

# tools that are there, but not registered by the setup yet (the plugin does not use them then)
_UNREGISTERED = set()


def _executable(path):
    # the absolute path of an executable path or command name, else ''
    try:
        if path and IsExecutable(path):
            return path if os.path.isabs(path) else Which(path)
    except Exception:
        printExc()
    return ''


def _probeToolPaths():
    # first line of the probe script: the path of every tool the plugin really runs - the one the setup
    # (or the hidden options) registered, not only the one in PATH
    _UNREGISTERED.clear()
    paths = {}
    for key, var, option, candidates in _SETUP_TOOLS:
        try:
            path = _executable(getattr(config.plugins.iptvplayer, option).value.strip())
        except Exception:
            path = ''
        if not path:
            for candidate in candidates():
                path = _executable(candidate)
                if path:
                    _UNREGISTERED.add(key)
                    break
        paths[var] = path
    paths['LS'] = GetBinDir('lsdir')  # local media runs the one of the platform folder
    paths['FF'] = _executable(GetFFmpegPath())
    paths['QJ'] = GetQjsPath()
    try:
        from Plugins.Extensions.IPTVPlayer.libs import curlimpersonate
        paths['CI'] = curlimpersonate.getImpersonateBinary()
    except Exception:
        printExc()
        paths['CI'] = ''

    def q(value):
        return "'%s'" % (value or '').replace("'", "'\\''")
    return '; '.join('%s=%s' % (var, q(paths[var])) for var in sorted(paths)) + '\n'

_PROBE_CACHE = None       # parsed binary block, reused for the whole session
_PROBE_KEEPALIVE = None   # holds the iptv_system object until its callback fires
_STARTUP_KEEPALIVE = None
_SNAPSHOT_LOGGED = False   # the full snapshot is already in the current log


def _log_snapshot(si):
    """Write the full system snapshot into the debug log, at most once per
    log (reset when the log is cleared)."""
    global _SNAPSHOT_LOGGED
    if _SNAPSHOT_LOGGED:
        return
    _SNAPSHOT_LOGGED = True
    try:
        printDBG("=== E2iPlayer system info ===\n"
                 + _SystemInfo.toPlain(si.buildSystemText(withBinaries=True))
                 + "\n=== end system info ===")
    except Exception:
        printExc()


def _free_space(path):
    try:
        st = os.statvfs(path)
        return "%s %s / %s" % (
            formatBytes(st.f_bavail * st.f_frsize, 1), _("free"),
            formatBytes(st.f_blocks * st.f_frsize, 1),
        )
    except Exception:
        return "?"


def _ram():
    # MemAvailable: what programs can still get without swapping (page cache counts as free)
    kv = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    kv[parts[0].rstrip(":")] = int(parts[1]) * 1024
    except Exception:
        return "?"
    total = kv.get("MemTotal", 0)
    free = kv.get("MemAvailable", kv.get("MemFree", 0))
    if not total:
        return "?"
    return "%s %s / %s" % (formatBytes(free, 1), _("free"), formatBytes(total, 1))


def _clock():
    # a clock that is not set (no NTP yet) makes every HTTPS certificate look invalid
    now = time.time()
    text = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(now))
    if time.gmtime(now).tm_year < 2025:
        text += "  (%s)" % _("clock not set")
    return text


def _ipv6():
    # in use when the box has a global IPv6 address and a default route that is not on lo
    try:
        with open("/proc/net/if_inet6") as f:
            hasAddr = any(p[3] == "00" and p[5] != "lo" for p in (line.split() for line in f) if len(p) >= 6)
        hasRoute = False
        if hasAddr:
            with open("/proc/net/ipv6_route") as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 10 and p[0] == "0" * 32 and p[1] == "00" and p[9] != "lo" and int(p[8], 16) & 1:
                        hasRoute = True
                        break
        return _("Yes") if hasAddr and hasRoute else _("No")
    except Exception:
        return "?"


def _shortPath(path):
    # the plugin folder is long and the same on every box: IPTVPlayer/bin/hlsdl is enough
    base = GetPluginDir('')
    if path.startswith(base):
        return "IPTVPlayer/" + path[len(base):]
    return path


def _read_first_line(path):
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except Exception:
        pass
    return ""


def _debug_log_path():
    """The resolved debug file path, or '' when the log is off / to console."""
    try:
        return GetDebugLogPath() or ""
    except Exception:
        return ""


def aboutBlocks():
    """(heading, text) pairs of the About page."""
    stamp = GetIPTVPlayerComitStamp()
    version = "E2iPlayer zadmario Version\n" + GetIPTVPlayerVersion() + (("  (" + stamp + ")") if stamp else "")
    return [
        (_("version"), version),
        (_("www:"), "https://github.com/oe-mirrors/e2iplayer-zadmario\nhttps://gitlab.com/zadmario/e2iplayer"),
        (_("Lead programmer:"), "samsamsam"),
        (_("Developers:"), ", ".join([
            'zdzislaw22', 'mamrot', 'MarcinO', 'skalita', 'atilaks',
            'huball', 'matzg', 'tomashj291', 'a4tech', 'Blindspot76',
            'Max (maxbambi)', '-=Mario=- (zadmario)', 'MohamedOS', 'Lululla (Belfagor2005)',
            'jbleyel', 'Mr.X', 'and others',
        ])),
        (_("Testers:"), ", ".join(('Masta2002', 'Testing Community: Enigma2 users worldwide'))),
        (_("Skinners:"), ", ".join(('stein17', 'and others'))),
    ]


class _SystemInfo(object):
    """Everything needed to gather + render the System page. No UI, so it
    can also be used headless at plugin start."""

    def __init__(self):
        self._systemBinaries = ""
        self._probe = None

    # ---------------------------------------------------------- gathering

    def _safeDir(self, fnc):
        try:
            p = fnc('')
            return p if p and os.path.isdir(p) else ""
        except Exception:
            return ""

    def _image(self):
        name = GetImageName()  # /etc/os-release PRETTY_NAME
        if name:
            return name
        # /etc/image-version: key=value lines - fallback for images without
        # a usable os-release
        kv = {}
        try:
            with open("/etc/image-version") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.split("=", 1)
                        kv[k.strip().lower()] = v.strip()
        except Exception:
            pass
        for combo in (("creator", "version"), ("distro", "imageversion"), ("distro", "version")):
            if all(k in kv for k in combo):
                return " ".join(kv[k] for k in combo)
        if "version" in kv:
            return kv["version"]
        line = _read_first_line("/etc/issue")
        if line:
            for junk in ("\\n", "\\l", "\\r", "\\s", "\\m"):
                line = line.replace(junk, "")
            return line.strip()
        return "?"

    def _boxtype(self):
        # boxbranding is what Enigma2 itself uses - baked into the image at
        # build time. /proc/stb/info/* is whatever the running kernel /
        # drivers report, which on ported or clone hardware can be a
        # completely different (and misleading) box id.
        official = ""
        try:
            import boxbranding
            btype = boxbranding.getBoxType()
            brand = boxbranding.getMachineBrand()
            name = boxbranding.getMachineName()
            official = ("%s %s" % (brand, name)).strip()
            if btype and btype.lower() not in official.lower():
                official = "%s (%s)" % (official, btype) if official else btype
        except Exception:
            pass

        kernel = ""
        for path in ("/proc/stb/info/model", "/proc/stb/info/boxtype", "/proc/stb/info/vumodel"):
            kernel = _read_first_line(path)
            if kernel:
                break

        if official and kernel and kernel.lower() not in official.lower():
            return "%s   [%s: %s]" % (official, _("kernel reports"), kernel)
        return official or kernel or "?"

    def _pycurlVersion(self):
        try:
            import pycurl
            return pycurl.version.split()[0] if getattr(pycurl, "version", "") else "?"
        except Exception:
            return _("not installed (urllib is used)")

    def _ifdsrcState(self, pkg):
        # gstplayer only buffers via ifd:// with this GStreamer plugin: the opkg package, or the file
        # the setup / a feed install puts there
        if pkg:
            return pkg[0].split(" - ", 1)[-1]
        path = "/usr/lib/gstreamer-1.0/libgstifdsrc.so"
        if os.path.isfile(path):
            return "%s (%s)" % (_("installed"), path)
        return _("not installed")

    def _moduleVersion(self, name, oldVersionAttr=""):
        # oldVersionAttr: where old releases keep the version (Pillow < 6: PILLOW_VERSION)
        try:
            mod = __import__(name)
        except Exception:
            return _("not installed")
        v = getattr(mod, "__version__", "") or (getattr(mod, oldVersionAttr, "") if oldVersionAttr else "")
        return str(v) if v else _("installed")

    def _websocketVersion(self):
        # the image's websocket-client, else the copy in IPTVPlayer/libs/websocket
        v = self._moduleVersion("websocket")
        if v != _("not installed"):
            return v
        try:
            from Plugins.Extensions.IPTVPlayer.libs import websocket
            return "%s (%s)" % (getattr(websocket, "__version__", "?"), _("bundled with the plugin"))
        except Exception:
            return v

    def _cryptoVersion(self):
        # "Crypto" is the old pycrypto (2.x) or pycryptodome (3.x); pycryptodomex installs as "Cryptodome",
        # which the plugin does not import
        found = []
        try:
            import Crypto
            v = str(getattr(Crypto, "__version__", "") or "?")
            found.append("%s %s" % ("pycryptodome" if v[:1].isdigit() and int(v.split(".")[0]) >= 3 else "pycrypto", v))
        except Exception:
            pass
        try:
            import Cryptodome
            found.append("pycryptodomex %s (%s)" % (getattr(Cryptodome, "__version__", "?"), _("not used")))
        except Exception:
            pass
        return ", ".join(found) or _("not installed")

    def _torrserverPath(self):
        # only the path: running the binary for a version could start the server
        try:
            from Plugins.Extensions.IPTVPlayer.libs import torrserver
            return torrserver.findBinary() or _("not installed (no torrent playback)")
        except Exception:
            printExc()
            return "?"

    def _subparserVersion(self):
        try:
            from Plugins.Extensions.IPTVPlayer.libs.iptvsubparser import _subparser
        except Exception as e:
            # the interpreter's own message is English and gets cut off by the two-column layout: the page
            # only says what it means for the user, the full text goes to the debug log
            printDBG("System info: the subtitles parser extension (_subparser) cannot be imported: %s" % e)
            return _("not available (the Python parser is used)")
        try:
            return str(_subparser.version())
        except Exception:
            return _("loaded (no version)")

    def _impersonateState(self):
        # sites this session loads with Chrome's fingerprint (pCommon) and the profile that works - '' when none yet
        try:
            from Plugins.Extensions.IPTVPlayer.libs import pCommon, curlimpersonate
            domains = sorted(pCommon._impersonateDomains.copy())  # copy(): worker threads may add meanwhile
            if not domains:
                return ""
            profile = curlimpersonate._state.get("profile") or curlimpersonate.PROFILES[0]
            return "%s: %s" % (profile, ", ".join(domains))
        except Exception:
            printExc()
            return ""

    # --------------------------------------------------------- rendering

    def _parseProbe(self, data):
        sections, cur = {}, None
        for raw in data.splitlines():
            line = raw.rstrip()
            if line.startswith("@@"):
                cur = line[2:]
                if cur != "end":
                    sections[cur] = []
                continue
            if cur and cur in sections and line.strip():
                sections[cur].append(line.strip())

        def tool(key):
            # (the output lines, the path - '' when the tool is missing); the path is the last line of a section
            v = sections.get(key) or []
            path = v[-1] if v else "-"
            return v[:-1], ("" if path == "-" else path)

        def withPath(key, value, path):
            # the path the plugin runs the tool from; a tool the setup has not registered is not used yet
            value = "%s (%s)" % (value, _shortPath(path))
            if key in _UNREGISTERED:
                value += " - " + _("not registered yet, run the E2iPlayer setup")
            return value

        # every renderer gets the text for a missing tool: what the user loses without it
        def first(key, missing):
            lines, path = tool(key)
            if not path:
                return missing
            return withPath(key, lines[0] if lines else _("installed"), path)

        def ver_line(key, missing):
            lines, path = tool(key)
            if not path:
                return missing
            for line in lines:
                low = line.lower()
                if line.startswith("{") or "version" in low or " v0." in low or " v1." in low:
                    return withPath(key, line, path)
            return withPath(key, lines[0] if lines else _("installed"), path)

        def lsdir_val(missing):
            lines, path = tool("lsdir")
            if not path:
                return missing
            for line in lines:
                if line.lower().startswith("lsdir v"):
                    return withPath("lsdir", line, path)
            return withPath("lsdir", _("installed"), path)

        def banner(key, missing):
            lines, path = tool(key)
            if not path:
                return missing
            line = lines[0] if lines else ""
            if line.lower().startswith("version:"):
                line = "v" + line.split(":", 1)[1].strip()
            return withPath(key, line or _("installed"), path)

        def path_val(key, missing):
            # a version line (or none) + the path, e.g. "curl 8.22.0-IMPERSONATE (arm-...) libcurl/...",
            # "UnZip 6.00 of 20 April 2009, by ...", "BusyBox v1.36.1 (2024-...) multi-call binary.",
            # "UNRAR 7.00 freeware      Copyright (c) ...", "Version 0.0.8" (uchardet)
            lines, path = tool(key)
            if not path:
                return missing
            ver = " ".join(lines[0].split()) if lines else ""
            for sep in (" (", " of ", " freeware", " Copyright", " built on "):
                ver = ver.split(sep, 1)[0]
            return withPath(key, ver or _("installed"), path)

        def row(name, value):
            return "%s|%s" % (name, value)

        notInstalled = _("not installed")
        # one JavaScript engine / one external player is enough: the reason only when all are missing
        noJs = not tool("duktape")[1] and not tool("quickjs")[1]
        jsMissing = _("not installed (hosts that need JavaScript fail)") if noJs else notInstalled
        noPlayer = not any(tool(key)[1] for key in ("exteplayer3", "gstplayer", "gstplayer2"))
        playerMissing = _("not installed (only the Enigma2 players)") if noPlayer else notInstalled

        out = ["--- e2iplayer-deps ---"]
        out.append(row("hlsdl", first("hlsdl", _("not installed (no HLS downloads or buffering)"))))
        out.append(row("_subparser", self._subparserVersion()))
        out.append(row("cmdwrap", banner("cmdwrap", _("not installed (no ffmpeg downloads)"))))
        out.append(row("lsdir", lsdir_val(_("not installed (no local media / folder browser)"))))
        out.append(row("f4mdump", banner("f4mdump", _("not installed (no HDS/F4M streams)"))))
        out.append(row("curl-impersonate", path_val("curlimp", _("not installed (sites with bot protection may fail)"))))
        imp = self._impersonateState()
        if imp:
            out.append(row("  " + _("as Chrome this session"), imp))
        deps = sections.get("deps") or []
        if deps:
            out.append(row("deps pkg", deps[0]))

        out.append("")
        out.append("--- " + _("other binaries") + " ---")
        out.append(row("ffmpeg", path_val("ffmpeg", _("not installed (no DASH / ffmpeg downloads)"))))
        out.append(row("wget", path_val("wget", _("not installed (no file, cover or subtitle downloads)"))))
        out.append(row("curl", path_val("curl", _("not installed (wget is used)"))))
        out.append(row("rtmpdump", path_val("rtmpdump", _("not installed (no RTMP downloads)"))))
        out.append(row("duktape", first("duktape", jsMissing)))
        out.append(row("quickjs", first("quickjs", jsMissing)))
        out.append(row("exteplayer3", ver_line("exteplayer3", playerMissing)))
        out.append(row("gstplayer", ver_line("gstplayer", playerMissing)))
        out.append(row("gstplayer2", ver_line("gstplayer2", playerMissing)))
        out.append(row("gst-ifdsrc", self._ifdsrcState(sections.get("ifdsrc") or [])))
        out.append(row("uchardet", path_val("uchardet", _("not installed (subtitles: code page of the language)"))))
        out.append(row("unzip", path_val("unzip", _("not installed (no ZIP subtitles)"))))
        out.append(row("unrar", path_val("unrar", _("not installed (no RAR subtitles)"))))
        out.append(row("TorrServer", self._torrserverPath()))

        out.append("")
        out.append("--- " + _("Python modules") + " ---")
        out.append(row("pycurl", self._pycurlVersion()))
        out.append(row("Pillow (PIL)", self._moduleVersion("PIL", "PILLOW_VERSION")))
        out.append(row("websocket-client", self._websocketVersion()))
        out.append(row("Crypto", self._cryptoVersion()))
        return "\n".join(out)

    def buildSystemText(self, withBinaries=True):
        lines = []

        def row(label, value):
            lines.append("%s|%s" % (label, value))

        lines.append("--- E2iPlayer ---")
        ver = GetIPTVPlayerVersion()
        stamp = GetIPTVPlayerComitStamp()
        row(_("version"), ver + (("  " + stamp) if stamp else ""))
        row("Python", "%s (%s)" % (GetShortPythonVersion(), sys.version.split()[0]))

        lines.append("")
        lines.append("--- " + _("System") + " ---")
        row(_("Image"), self._image())
        row(_("Box"), self._boxtype())
        uname = os.uname()
        row("CPU", uname[4])
        row("Kernel", uname[2])
        row(_("RAM"), _ram())
        row(_("Time"), _clock())
        row("IPv6", _ipv6())

        lines.append("")
        lines.append("--- " + _("Storage") + " ---")
        for label, path in ((_("Config"), self._safeDir(GetConfigDir)),
                            (_("Temp"), self._safeDir(GetTmpDir))):
            if path:
                row(label, "%s  [%s]" % (_free_space(path), path))
        # the folders set in the settings: a full or unmounted disk is a common cause of failed downloads
        for label, cfg in ((_("Downloads"), "NaszaSciezka"), (_("Buffering location"), "bufferingPath")):
            try:
                path = getattr(config.plugins.iptvplayer, cfg).value
            except Exception:
                continue
            if path:
                row(label, "%s  [%s]" % (_free_space(path) if os.path.isdir(path) else _("not found"), path))

        lines.append("")
        lines.append("--- " + _("Debug log") + " ---")
        logp = _debug_log_path()
        if logp:
            sz = ""
            try:
                sz = "  (%s)" % formatBytes(os.path.getsize(logp), 1)
            except Exception:
                pass
            row(_("file"), logp + sz)
        else:
            row(_("status"), _("off / console"))

        if withBinaries:
            lines.append("")
            lines.append(self._systemBinaries or ("--- " + _("Binaries") + " ---\n" + _("(reading...)")))

        return "\n".join(lines)

    @staticmethod
    def toPlain(text):
        """label|value -> aligned 'label:  value' for the saved file / log."""
        out = []
        for line in text.split("\n"):
            if "|" in line and not line.lstrip().startswith("-"):
                a, b = line.split("|", 1)
                out.append("%-19s %s" % (a + ":", b))
            else:
                out.append(line)
        return "\n".join(out)

    @staticmethod
    def toRows(text):
        """The System text as rows of the two-column list: ('head', text),
        ('row', label, value) or ('gap',)."""
        rows = []
        for line in text.split("\n"):
            stripped = line.strip()
            if not stripped:
                rows.append(('gap',))
            elif stripped.startswith("---"):
                rows.append(('head', stripped.strip("- ")))
            elif "|" in line:
                a, b = line.split("|", 1)
                rows.append(('row', a, b))
            else:
                rows.append(('row', '', stripped))
        return rows

    # ------------------------------------------------------------- probe

    def runProbe(self, onDone):
        """Fill self._systemBinaries (async) then call onDone(). Uses the
        module-level cache, so it only ever actually probes once."""
        global _PROBE_KEEPALIVE
        self._systemBinaries = ""
        if _PROBE_CACHE:
            self._systemBinaries = _PROBE_CACHE
            onDone()
            return

        def _cb(code, data):
            global _PROBE_CACHE, _PROBE_KEEPALIVE
            _PROBE_KEEPALIVE = None
            self._probe = None
            try:
                self._systemBinaries = self._parseProbe(data or "")
                _PROBE_CACHE = self._systemBinaries
            except Exception:
                printExc()
                self._systemBinaries = (data or "").strip()
            try:
                onDone()
            except Exception:
                printExc()

        try:
            with open(_PROBE_SCRIPT_PATH, "w") as f:
                f.write(_probeToolPaths() + _PROBE_SCRIPT)
            self._probe = iptv_system("sh %s; rm -f %s" % (_PROBE_SCRIPT_PATH, _PROBE_SCRIPT_PATH), _cb)
            _PROBE_KEEPALIVE = self._probe
        except Exception:
            printExc()
            self._probe = None
            self._systemBinaries = _("could not run the probe")
            onDone()


class _InfoRowsList(IPTVListComponentBase):
    # the System page: headings (accent colour) and label | value rows

    def __init__(self, fontSize, itemHeight, labelW):
        IPTVListComponentBase.__init__(self)
        self.itemHeight = itemHeight
        self.labelW = labelW
        self.l.setFont(0, gFont("Regular", fontSize))
        self.l.setItemHeight(itemHeight)

    def onCreate(self):
        pass

    def onDestroy(self):
        pass

    def buildEntry(self, item):
        res = [None]
        width = self.l.getItemSize().width()
        height = self.l.getItemSize().height()
        flags = RT_HALIGN_LEFT | RT_VALIGN_CENTER
        if item[0] == 'head':
            res.append((eListboxPythonMultiContent.TYPE_TEXT, 0, 0, width, height, 0, flags, toNative(item[1]), _HEADING_COLOR))
        elif item[0] == 'row':
            res.append((eListboxPythonMultiContent.TYPE_TEXT, 10, 0, self.labelW - 10, height, 0, flags, toNative(item[1]), _TEXT_COLOR))
            res.append((eListboxPythonMultiContent.TYPE_TEXT, self.labelW, 0, width - self.labelW, height, 0, flags, toNative(item[2]), _TEXT_COLOR))
        return res


class IPTVPlayerInfoView(_SystemInfo, Screen):
    COLOR_KEYS = ('green', 'yellow', 'blue')

    def prepareSkin(self):
        tier, scale = GetVKTier()
        self.tier = tier
        # a plain image window like the settings, the page in its title
        # bar, the colour keys on top like in the main window
        width, height = _s(1200, scale), _s(620, scale)
        keysY = _s(10, scale)
        x, y = _s(20, scale), keysY + _s(30, scale) + _s(16, scale)
        w, h = width - 2 * x, height - y - _s(12, scale)
        # whole list rows in the System page
        self.rowHeight = _s(30, scale)
        h = h // self.rowHeight * self.rowHeight
        self.fontSize = _s(20, scale)
        self.labelW = _s(230, scale)

        skinTab = ['<screen position="center,center" size="%d,%d" title="E2iPlayer">' % (width, height)]
        for slotIdx, color in enumerate(self.COLOR_KEYS):
            skinTab.append(colorKeySkin(color, slotIdx, keysY, scale))
        skinTab.append('<widget name="about" position="%d,%d" size="%d,%d" font="Regular;%d" halign="center" transparent="1" backgroundColor="#00000000" />' % (x, y, w, h, self.fontSize))
        skinTab.append('<widget name="system" position="%d,%d" size="%d,%d" zPosition="1" transparent="1" backgroundColor="#00000000" scrollbarMode="showOnDemand" />' % (x, y, w, h))
        skinTab.append('<widget name="log" position="%d,%d" size="%d,%d" font="Regular;%d" transparent="1" backgroundColor="#00000000" />' % (x, y, w, h, _s(18, scale)))
        skinTab.append('</screen>')
        return '\n'.join(skinTab)

    def __init__(self, session, aboutText=""):
        _SystemInfo.__init__(self)
        self.skin = self.prepareSkin()
        Screen.__init__(self, session)

        self._page = PAGE_ABOUT
        self._aboutText = aboutText or self._buildAbout()
        self._systemText = ""
        self._logAutoRefresh = True
        self._closed = False

        self["about"] = ScrollLabel(" ")
        self["system"] = _InfoRowsList(self.fontSize, self.rowHeight, self.labelW)
        self["log"] = ScrollLabel(" ")
        for color in self.COLOR_KEYS:
            self["key_%s" % color] = Label(" ")
            self["key_%s_icon" % color] = Pixmap()

        self["actions"] = ActionMap(["OkCancelActions", "DirectionActions", "ColorActions"],
        {
            "cancel": self.close,
            "ok": self.close,
            "up": self._pageUp,
            "down": self._pageDown,
            "left": self._prevPage,
            "right": self._nextPage,
            "green": self._save,
            "yellow": self._toggleAutoRefresh,
            "blue": self._clearLog,
        }, -1)

        self._logTimer = eTimer()
        self._logTimer_conn = eConnectCallback(self._logTimer.timeout, self._refreshLog)

        self.onLayoutFinish.append(self._onStart)
        self.onClose.append(self._onClose)

    # ---------------------------------------------------------------- lifecycle

    def _onStart(self):
        self.onLayoutFinish.remove(self._onStart)
        try:
            self["system"].setSelectionState(False)
        except Exception:
            printExc()
        self.runProbe(self._finishSystem)
        self._showPage()

    def _onClose(self):
        self._closed = True
        try:
            self._logTimer.stop()
        except Exception:
            pass
        self._logTimer = None
        self._logTimer_conn = None
        # do not terminate self._probe - _PROBE_KEEPALIVE lets it finish
        # and populate the cache even if the screen is closed at once

    # ------------------------------------------------------------------- paging

    def _nextPage(self):
        self._page = (self._page + 1) % 3
        self._showPage()

    def _prevPage(self):
        self._page = (self._page - 1) % 3
        self._showPage()

    def _pageUp(self):
        self._scroll(-1)

    def _pageDown(self):
        self._scroll(1)

    def _scroll(self, direction):
        if self._page == PAGE_SYSTEM:
            inst = self["system"].instance
            if inst is not None:
                inst.moveSelection(inst.pageUp if direction < 0 else inst.pageDown)
        else:
            view = self["about"] if self._page == PAGE_ABOUT else self["log"]
            if direction < 0:
                view.pageUp()
            else:
                view.pageDown()

    def _setKeys(self, green, yellow="", blue=""):
        # a colour key without a function is not shown at all
        for color, text in (('green', green), ('yellow', yellow), ('blue', blue)):
            self["key_%s" % color].setText(toNative(text or " "))
            for name in ("key_%s" % color, "key_%s_icon" % color):
                if text:
                    self[name].show()
                else:
                    self[name].hide()

    def _showPage(self):
        self._logTimer.stop()
        name = PAGE_NAMES.get(self._page, lambda: "")()
        title = "E2iPlayer - %s  (%d/3)" % (name, self._page + 1)
        self.setTitle(title)
        for page, widget in ((PAGE_ABOUT, "about"), (PAGE_SYSTEM, "system"), (PAGE_LOG, "log")):
            if page == self._page:
                self[widget].show()
            else:
                self[widget].hide()

        if self._page == PAGE_ABOUT:
            self["about"].setText(toNative(self._aboutText))
            self._setKeys(_("Save"))
        elif self._page == PAGE_SYSTEM:
            self._setSystemText(self._systemText or (self.buildSystemText(withBinaries=False) + "\n\n" + _("Reading binaries...")))
            self._setKeys(_("Save"))
        else:  # PAGE_LOG
            self._setKeys(_("Save"), self._autoRefreshLabel(), _("Clear log"))
            self._refreshLog()
            if self._logAutoRefresh:
                self._logTimer.start(LOG_REFRESH_MS, False)

    def _setSystemText(self, text):
        self["system"].setList([(row,) for row in self.toRows(text)])

    def _finishSystem(self):
        _log_snapshot(self)  # in case the startup probe never ran
        if self._closed:
            return
        self._systemText = self.buildSystemText(withBinaries=True)
        if self._page == PAGE_SYSTEM:
            self._setSystemText(self._systemText)

    # ------------------------------------------------------------------ content

    def _buildAbout(self):
        return "\n\n".join("%s\n%s" % (head, body) for head, body in aboutBlocks())

    # -------------------------------------------------------------------- log

    def _autoRefreshLabel(self):
        return _("Auto refresh: %s") % (_("on") if self._logAutoRefresh else _("off"))

    def _refreshLog(self):
        logp = _debug_log_path()
        if not logp:
            self["log"].setText(toNative(_("The debug log is disabled or set to console output.\n\nEnable it in the E2iPlayer configuration (Debug -> log to file) and reproduce the problem, then come back here.")))
            return
        text = self._tail(logp, LOG_TAIL_BYTES)
        if not text:
            text = _("The debug log file is empty:\n%s") % logp
        self["log"].setText(toNative(text))
        for mname in ("lastPage", "moveBottom", "moveEnd"):
            fn = getattr(self["log"], mname, None)
            if callable(fn):
                try:
                    fn()
                    break
                except Exception:
                    pass

    def _tail(self, path, nbytes):
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                if size > nbytes:
                    f.seek(size - nbytes)
                    f.readline()  # drop the partial first line
                data = f.read()
            return data.decode("utf-8", "ignore")
        except Exception:
            return ""

    def _toggleAutoRefresh(self):
        if self._page != PAGE_LOG:
            return
        self._logAutoRefresh = not self._logAutoRefresh
        self["key_yellow"].setText(toNative(self._autoRefreshLabel()))
        if self._logAutoRefresh:
            self._refreshLog()
            self._logTimer.start(LOG_REFRESH_MS, False)
        else:
            self._logTimer.stop()

    def _clearLog(self):
        if self._page != PAGE_LOG:
            return
        from Screens.MessageBox import MessageBox
        logp = _debug_log_path()
        if not logp or not os.path.exists(logp):
            self.session.open(MessageBox, _("The debug log is not active."), type=MessageBox.TYPE_INFO, timeout=6)
            return
        self.session.openWithCallback(self._clearLogConfirmed, MessageBox,
                                      _("Clear the debug log file?\n%s") % logp, type=MessageBox.TYPE_YESNO)

    def _clearLogConfirmed(self, answer):
        global _SNAPSHOT_LOGGED
        if not answer:
            return
        logp = _debug_log_path()
        try:
            open(logp, "w").close()
            _SNAPSHOT_LOGGED = False  # let the snapshot go into the fresh log
        except Exception:
            printExc()
        _log_snapshot(self)  # put the snapshot back at the top of the fresh log
        self._refreshLog()

    # ------------------------------------------------------------------- save

    def _save(self):
        from Screens.MessageBox import MessageBox
        try:
            if self._page == PAGE_LOG:
                logp = _debug_log_path()
                if not logp or not os.path.exists(logp):
                    self.session.open(MessageBox, _("Nothing to save - the debug log is not active."), type=MessageBox.TYPE_INFO, timeout=6)
                    return
                dst = DEBUGCOPY_FILE
                with open(dst, "wb") as f:
                    f.write(self._tail(logp, LOG_TAIL_BYTES * 8).encode("utf-8"))
            else:
                dst = SYSINFO_FILE
                with open(dst, "w") as f:
                    f.write("=== E2iPlayer - System ===\n\n")
                    f.write(self.toPlain(self._systemText or self.buildSystemText(withBinaries=True)))
                    f.write("\n\n\n=== E2iPlayer - About ===\n\n")
                    f.write(self._aboutText + "\n")
            self.session.open(MessageBox, _("Saved to:\n%s") % dst, type=MessageBox.TYPE_INFO, timeout=8)
        except Exception:
            printExc()
            self.session.open(MessageBox, _("Could not write the file."), type=MessageBox.TYPE_ERROR, timeout=8)


def LogSystemInfoAtStartup(force=False):
    """Called from plugin start: run the binary probe (cached after the
    first time) and write the full system snapshot near the top of the
    debug log. `force` re-logs it into a freshly cleared log."""
    global _STARTUP_KEEPALIVE, _SNAPSHOT_LOGGED
    if force:
        _SNAPSHOT_LOGGED = False
    if _SNAPSHOT_LOGGED:
        return
    si = _SystemInfo()
    _STARTUP_KEEPALIVE = si

    def _done():
        global _STARTUP_KEEPALIVE
        _log_snapshot(si)
        _STARTUP_KEEPALIVE = None

    try:
        si.runProbe(_done)
    except Exception:
        printExc()
        _STARTUP_KEEPALIVE = None


def OpenInfoView(session, aboutText=""):
    """Entry point used by the BLUE menu and the settings INFO key."""
    try:
        session.open(IPTVPlayerInfoView, aboutText)
        return True
    except Exception:
        printExc()
        return False

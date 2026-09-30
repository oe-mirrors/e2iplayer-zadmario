# -*- coding: utf-8 -*-
#
#  E2iPlayer info / diagnostics screen.
#
#  Opened from the BLUE menu -> "Info" and with INFO in the settings. Three
#  pages, switched with LEFT / RIGHT:
#
#    About   - version, project links, credits
#    System  - E2iPlayer / Python / image / box, every externally loaded
#              tool and its version, free space, the debug-log setting
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

from enigma import eTimer, eListboxPythonMultiContent, gFont, RT_HALIGN_LEFT, RT_VALIGN_CENTER
from Components.ActionMap import ActionMap
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
    GetConfigDir, GetTmpDir, GetDebugLogPath,
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
PAGE_NAMES = {PAGE_ABOUT: _("About"), PAGE_SYSTEM: _("System"), PAGE_LOG: _("Log")}

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
_PROBE_SCRIPT_PATH = "/tmp/.e2i_sysprobe.sh"

_P = '</dev/null 2>&1'
_PROBE_SCRIPT = (
    'T=""; if timeout 4 true >/dev/null 2>&1; then T="timeout 4"; '
    'elif timeout -t 4 true >/dev/null 2>&1; then T="timeout -t 4"; fi; '
    'w(){ command -v "$1" 2>/dev/null || echo "-"; }; '
    'echo "@@hlsdl";       ($T hlsdl %s            || true) | head -n 2; '
    'echo "@@cmdwrap";     ($T cmdwrap %s          || true) | head -n 1; '
    'echo "@@lsdir";       ($T lsdir --version %s  || true) | head -n 1; w lsdir; '
    'echo "@@f4mdump";     ($T f4mdump %s          || true) | head -n 1; '
    'echo "@@ffmpeg";      ($T ffmpeg -version %s   || true) | head -n 1; '
    'echo "@@wget";        ($T wget --version %s    || true) | head -n 1; '
    'echo "@@curl";        ($T curl --version %s    || true) | head -n 1; '
    'echo "@@rtmpdump";    ($T rtmpdump --help %s   || true) | grep -i rtmpdump | head -n 1; '
    'echo "@@exteplayer3"; ($T exteplayer3 %s       || true) | head -n 2; '
    'echo "@@gstplayer";   ($T gstplayer %s         || true) | head -n 2; '
    'echo "@@gstplayer2";  ($T gstplayer2 %s        || true) | head -n 2; '
    'echo "@@duktape";     D=/tmp/.e2i_dukver.js; '
    '  printf "%%s" \'try{var v=Duktape.version;print(Math.floor(v/10000)+"."+(Math.floor(v/100)%%100)+"."+(v%%100))}catch(e){print("?")}\' > $D; '
    '  ($T duk $D %s || true) | head -n 1; rm -f $D; '
    'echo "@@quickjs";     ($T qjs --version %s     || true) | head -n 1; '
    'echo "@@deps";        (opkg list-installed 2>/dev/null | grep -i e2iplayer-deps || true); '
    'echo "@@end"\n'
) % ((_P,) * 13)

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
            return _("not installed")

    def _pilVersion(self):
        try:
            import PIL
            v = getattr(PIL, "__version__", "") or getattr(PIL, "PILLOW_VERSION", "")
            return str(v) if v else _("installed")
        except Exception:
            return _("not installed")

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

        def first(key):
            v = sections.get(key) or []
            return v[0] if v else _("not found")

        def ver_line(key):
            v = sections.get(key) or []
            for line in v:
                low = line.lower()
                if line.startswith("{") or "version" in low or " v0." in low or " v1." in low:
                    return line
            return v[0] if v else _("not found")

        def lsdir_val():
            v = sections.get("lsdir") or []
            for line in v:
                if line.lower().startswith("lsdir v"):
                    return line
            tail = v[-1] if v else "-"
            return _("installed") if tail and tail != "-" else _("not installed")

        def banner(key):
            v = sections.get(key) or []
            if not v:
                return _("not installed")
            line = v[0].strip()
            if line.lower().startswith("version:"):
                line = "v" + line.split(":", 1)[1].strip()
            return line or _("installed")

        def row(name, value):
            return "%s|%s" % (name, value)

        out = ["--- e2iplayer-deps ---"]
        out.append(row("hlsdl", first("hlsdl")))
        out.append(row("_subparser", self._subparserVersion()))
        out.append(row("cmdwrap", banner("cmdwrap")))
        out.append(row("lsdir", lsdir_val()))
        out.append(row("f4mdump", banner("f4mdump")))
        deps = sections.get("deps") or []
        if deps:
            out.append(row("deps pkg", deps[0]))

        out.append("")
        out.append("--- " + _("other binaries") + " ---")
        out.append(row("ffmpeg", first("ffmpeg")))
        out.append(row("wget", first("wget")))
        out.append(row("curl", first("curl")))
        out.append(row("rtmpdump", first("rtmpdump")))
        out.append(row("duktape", first("duktape")))
        out.append(row("quickjs", first("quickjs")))
        out.append(row("exteplayer3", ver_line("exteplayer3")))
        out.append(row("gstplayer", ver_line("gstplayer")))
        out.append(row("gstplayer2", ver_line("gstplayer2")))

        out.append("")
        out.append("--- " + _("Python modules") + " ---")
        out.append(row("pycurl", self._pycurlVersion()))
        out.append(row("Pillow (PIL)", self._pilVersion()))
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

        lines.append("")
        lines.append("--- " + _("Storage") + " ---")
        for label, path in ((_("Config"), self._safeDir(GetConfigDir)),
                            (_("Temp"), self._safeDir(GetTmpDir))):
            if path:
                row(label, "%s  [%s]" % (_free_space(path), path))

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
                out.append("%-15s %s" % (a + ":", b))
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
                f.write(_PROBE_SCRIPT)
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
        name = PAGE_NAMES.get(self._page, "")
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

# -*- coding: utf-8 -*-
#

###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc, GetIconDir, eConnectCallback, E2PrioFix, GetPyScriptCmd, get_ip, is_port_in_use, GetTmpDir, rm
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.libs.web_qr import make_qr_png
###################################################

###################################################
# FOREIGN import
###################################################
from enigma import eConsoleAppContainer, eTimer
from Screens.Screen import Screen
from Screens.MessageBox import MessageBox
from Components.Label import Label
from Components.Pixmap import Pixmap
from Components.ActionMap import ActionMap
from Components.config import config
from Tools.LoadPixmap import LoadPixmap

from Plugins.Extensions.IPTVPlayer.p2p3.manipulateStrings import ensure_str, ensure_binary

try:
    import json
except Exception:
    import simplejson as json
import re
import base64
import binascii
import os
###################################################

# width the QR pixmap strip adds next to the console box, and the square QR pixmap's own size within it
_QR_STRIP_WIDTH = 220
_QR_SIZE = 178

WIKI_URL = 'https://github.com/oe-mirrors/e2iplayer/wiki/Solve-Cloudflare-hCaptcha-reCAPTCHA-with-MyE2i'


class MyE2iHelpScreen(Screen):
    # Small help window of the MyE2i captcha screen (YELLOW / INFO / HELP): what to do,
    # and a QR code that leads to the wiki page.
    WIDTH = 860
    HEIGHT = 380
    QR_SIZE = 220

    def __init__(self, session):
        Screen.__init__(self, session)
        textWidth = self.WIDTH - self.QR_SIZE - 50
        self.skin = """
            <screen position="center,center" title="MyE2iHelpScreen" size="%d,%d">
             <ePixmap position="5,9" zPosition="4" size="30,30" pixmap="%s" transparent="1" alphatest="on" />
             <widget name="label_exit" position="45,9" zPosition="5" size="175,27" valign="center" halign="left" backgroundColor="black" font="Regular;21" transparent="1" foregroundColor="white" shadowColor="black" shadowOffset="-1,-1" />
             <widget name="text" position="10,50" zPosition="2" size="%d,%d" font="Regular;20" transparent="1" foregroundColor="white" backgroundColor="black" />
             <widget name="qrcode" position="%d,50" size="%d,%d" zPosition="2" scale="1" alphatest="blend" transparent="1" />
            </screen>""" % (
                self.WIDTH, self.HEIGHT,
                GetIconDir('key_exit.png'),
                textWidth, self.HEIGHT - 60,
                self.WIDTH - self.QR_SIZE - 20, self.QR_SIZE, self.QR_SIZE,
            )
        self.setTitle(_("MyE2i - how to solve a captcha"))
        self["label_exit"] = Label(_("Close"))
        self["text"] = Label(self._helpText())
        self["qrcode"] = Pixmap()
        self["qrcode"].hide()
        self["actions"] = ActionMap(["SetupActions", "WizardActions"], {"cancel": self.close, "ok": self.close}, -2)
        self._qrPath = GetTmpDir("mye2i_help_qr.png")
        self.onLayoutFinish.append(self._showQr)
        self.onClose.append(self._removeQrFile)

    @staticmethod
    def _helpText():
        return "\n".join((
            _("How to solve a captcha:"),
            _("1. On a phone or PC in the same network, open the address shown in the captcha window (or scan its QR code) in a browser with the MyE2i extension installed. If it asks for a code, you find it in the title of the captcha window."),
            _("2. Click the big green button on that page. A new tab opens with the captcha or the website's browser check."),
            _("3. Solve it. The result goes back to the receiver by itself and the captcha window closes."),
            _("The QR code leads to the wiki page with pictures and the extension download."),
        ))

    def _showQr(self):
        try:
            make_qr_png(WIKI_URL, self._qrPath, scale=8, border=3)
            self["qrcode"].instance.setPixmap(LoadPixmap(self._qrPath))
            self["qrcode"].show()
        except Exception:
            printExc()

    def _removeQrFile(self):
        rm(self._qrPath)


class UnCaptchaReCaptchaMyE2iWidget(Screen):

    # Status texts printed by scripts/mye2iserver.py arrive here as plain
    # English strings and are translated through _(str(data)) - a dynamic call,
    # invisible to xgettext. Listing them as literals makes the translation
    # template pick them up.
    SERVER_STATUS_MESSAGES = (
        _("MyE2i extension is outdated - please update it."),
        _("MyE2i debug snapshot received - see the debug log."),
    )

    def __init__(self, session, title, sitekey, referer, captchaType, captchaAction='', captchaData=''):
        self.session = session
        Screen.__init__(self, session)
        self.sitekey = sitekey
        self.referer = referer
        self.captchaType = captchaType
        self.captchaAction = captchaAction
        self.captchaData = captchaData

        # Setting "MyE2i extension: increase security": a random per-session key (carried by the
        # QR code) and a short code (for the address typed by hand, shown in the window title);
        # mye2iserver.py then only accepts pages, results, debug lines and dumps that come with
        # one of them, so another device in the network cannot inject anything.
        # Off: no key, no code - the plain address opens the page directly.
        if config.plugins.iptvplayer.mye2i_security.value:
            self.sessionToken = binascii.hexlify(os.urandom(8)).decode('ascii')
            self.sessionPin = '%06d' % (int(binascii.hexlify(os.urandom(4)), 16) % 1000000)
            title = '%s   -   %s: %s' % (title, _("Code"), self.sessionPin)
        else:
            self.sessionToken = ''
            self.sessionPin = ''

        sz_w = 504 #getDesktop(0).size().width() - 190
        sz_h = 300 #getDesktop(0).size().height() - 195
        if sz_h < 500:
            sz_h += 4
        self.skin = """
            <screen position="center,center" title="%s" size="%d,%d">
             <ePixmap position="5,9"   zPosition="4" size="30,30" pixmap="%s" transparent="1" alphatest="on" />
             <ePixmap position="225,9" zPosition="4" size="30,30" pixmap="%s" transparent="1" alphatest="on" />

             <widget name="label_red"    position="45,9"  zPosition="5" size="175,27" valign="center" halign="left" backgroundColor="black" font="Regular;21" transparent="1" foregroundColor="white" shadowColor="black" shadowOffset="-1,-1" />
             <widget name="label_yellow" position="265,9" zPosition="5" size="175,27" valign="center" halign="left" backgroundColor="black" font="Regular;21" transparent="1" foregroundColor="white" shadowColor="black" shadowOffset="-1,-1" />
             <widget name="title"        position="5,47"  zPosition="1" size="%d,23" font="Regular;20"            transparent="1"  backgroundColor="#00000000"/>
             <widget name="console"      position="10,%d" zPosition="2" size="%d,160" valign="center" halign="center"   font="Regular;24" transparent="0" foregroundColor="white" backgroundColor="black"/>
             <widget name="qrcode"       position="%d,%d" size="%d,%d" zPosition="2" scale="1" alphatest="blend" transparent="1" />
            </screen>""" % (
                title,
                sz_w + _QR_STRIP_WIDTH, sz_h,   # size
                GetIconDir('red' + '.png'),
                GetIconDir('yellow' + '.png'),
                sz_w - 135,                # size title
                (sz_h - 160) / 2, sz_w - 20, # console
                sz_w + (_QR_STRIP_WIDTH - _QR_SIZE) // 2 - 10, 66, _QR_SIZE, _QR_SIZE, # QR code
                )

        self.onShown.append(self.onStart)
        self.onClose.append(self.__onClose)

        self["title"] = Label(" ")
        self["console"] = Label(" ")
        # scale="1" is required for the QR pixmap - without it Enigma2 draws the loaded
        # pixmap at its native size instead of fitting it into the widget.
        self["qrcode"] = Pixmap()
        self["qrcode"].hide()  # shown once startExecution() has an image to put in it

        self["label_red"] = Label(_("Cancel"))
        self["label_yellow"] = Label(_("Help"))

        self["actions"] = ActionMap(["ColorActions", "SetupActions", "WizardActions", "ListboxActions"],
            {
                "cancel": self.keyExit,
                #"ok"    : self.keyOK,
                "red": self.keyRed,
            }, -2)
        self["helpactions"] = ActionMap(["ColorActions", "IPTVPlayerListActions"], {"yellow": self.keyHelp, "info": self.keyHelp}, -2)

        self.workconsole = {'console': None, 'close_conn': None, 'stderr_conn': None, 'stdout_conn': None, 'stderr': '', 'stdout': ''}
        self.result = ''

        self.timer = {'timer': eTimer(), 'is_started': False}
        self.timer['callback_conn'] = eConnectCallback(self.timer['timer'].timeout, self._timoutCallback)
        self.errorCodeSet = False

        self.ip_address = get_ip()
        self.port = 9001
        self._qrPath = GetTmpDir("mye2i_web_access_qr.png")
        self.onClose.append(self._removeQrFile)

    def _serverTexts(self):
        # Everything mye2iserver.py and the browser extension show in the browser
        # (see DEFAULT_TEXTS there - the keys and the English texts must match).
        # The server is a stand-alone script without translation, so the plugin
        # translates here and hands the result over; a text without translation
        # simply stays English.
        return {
            'pin_prompt': _("Enter the code shown in the title of the window on your receiver's screen (or scan the QR code shown there - no code needed then):"),
            'pin_continue': _("Continue"),
            'pin_no_session_code': _("This session has no code - scan the QR code on the receiver screen."),
            'pin_locked': _("Too many wrong codes - scan the QR code on the receiver screen instead."),
            'pin_wrong': _("Wrong code."),
            'extension_outdated': _("Your MyE2i extension is outdated or unknown (v%s or newer needed). Please update:"),
            'extension_download': _("Download new version"),
            'job_cloudflare': _("Get Cloudflare job"),
            'job_cookies': _("Get cookies job"),
            'job_captcha': _("Get captcha job"),
            'status_waiting': _("Waiting for the result ..."),
            'debug_pill': _("debug"),
            'debug_title': _("Debug snapshot (for site development)"),
            'debug_text': _("Needs extension v1.18+. Opens the page in this browser, waits until it is fully rendered (Cloudflare challenge included, solve it if it shows up) and sends the rendered HTML, the fetch/XHR calls and the cookie names to the box debug log."),
            'debug_button': _("Debug snapshot"),
            'err_title': _("Error"),
            'err_forbidden': _("Access denied - open the page with the QR code or the code shown on the receiver screen."),
            'err_not_found': _("Page not found - please check the address."),
            'err_bad_length': _("The request has no valid length."),
            'err_too_large': _("The data is too large."),
            'x_done': _("Done - the result was sent to the box, you can close this page."),
            'x_send_failed': _("Sending the result to the box failed."),
            'x_dump_ok': _('Debug snapshot: "%s" received by the box'),
            'x_dump_failed': _('Debug snapshot: sending "%s" failed'),
            'x_error': _("Error occurs:"),
            'header_please_solve': _("Please solve to continue downloads with:"),
            'help_whats_happening_header': _("What's happening?"),
            'help_whats_happening_description': _("wants you to solve a captcha. Only after solving this captcha, you are allowed to continue with your downloads. E2iPlayer is not able to auto-solve these captchas, so we need to pass the captcha to you."),
            'help_whats_happening_link': _("Find out more."),
            'button_i_am_no_robot': _("I am no robot"),
            'button_please_wait': _("Please wait..."),
            'captcha_error': _("Captcha error:"),
        }

    def _timoutCallback(self):
        self.timer['is_started'] = False
        self.close(self.result)

    def __onClose(self):
        self.workconsole['close_conn'] = None
        self.workconsole['stderr_conn'] = None
        self.workconsole['stdout_conn'] = None
        if self.workconsole['console']:
            self.workconsole['console'].sendCtrlC()
        self.workconsole['console'] = None

        if self.timer['is_started']:
            self.timer['timer'].stop()
        self.timer['callback_conn'] = None
        self.timer = None

    def _removeQrFile(self):
        rm(self._qrPath)

    def keyHelp(self):
        self.session.open(MyE2iHelpScreen)

    def _scriptClosed(self, code=0):
        if code == 0:
            self["console"].setText(_('MyE2i script finished.'))
            self.close(self.result)
        elif not self.errorCodeSet:
            self["console"].setText(_("MyE2i script execution failed.\nError code: %s\n") % (code))

    def _scriptStderrAvail(self, data):
        hadResult = bool(self.result)
        data = ensure_str(data)
        self.workconsole['stderr'] += data
        self.workconsole['stderr'] = self.workconsole['stderr'].split('\n')
        if data.endswith('\n'):
            data = ''
        else:
            data = self.workconsole['stderr'].pop(-1)
        for line in self.workconsole['stderr']:
            line = line.strip()
            if line == '':
                continue
            line = re.findall("{.*}", line)
            if len(line) == 0:
                continue
            try:
                line = json.loads(line[0])
                if line['type'] == 'captcha_result':
                    self.result = line['data']
                    # timeout timer
                    if self.timer['is_started']:
                        self.timer['timer'].stop()
                    # start timeout timer 3s
                    self.timer['timer'].start(3000, True)
                    self.timer['is_started'] = True
                    self["console"].setText(_('Captcha solved.\nWaiting for notification.'))
                elif line['type'] == 'status':
                    self["console"].setText(_(ensure_str(line['data'])))
                elif line['type'] == 'popup':
                    # a note that must not be missed but does not replace the console text
                    self.session.open(MessageBox, _(ensure_str(line['data'])), type=MessageBox.TYPE_INFO, timeout=10)
                elif line['type'] == 'error':
                    if line['code'] == 500:
                        self["console"].setText(_('Invalid email.'))
                    elif line['code'] == 403:
                        self["console"].setText(_('Access denied. Please check password.'))
                    else:
                        self["console"].setText(_("Error code: %s\nError message: %s") % (line['code'], line['data']))
                    self.errorCodeSet = True
            except Exception:
                printExc('Current line |%s|' % str(line))
        self.workconsole['stderr'] = data
        if not hadResult and self.result:
            # captcha just got solved - the QR code (and the file behind it)
            # served its purpose, drop both instead of leaving them lying around.
            self["qrcode"].hide()
            self._removeQrFile()

    def _scriptStdoutAvail(self, data):
        data = ensure_str(data)
        self.workconsole['stdout'] += data
        self.workconsole['stdout'] = self.workconsole['stdout'].split('\n')
        if data.endswith('\n'):
            data = ''
        else:
            data = self.workconsole['stdout'].pop(-1)
        for line in self.workconsole['stdout']:
            printDBG(line)
        self.workconsole['stdout'] = data

    def startExecution(self):
        captcha = {'siteKey': self.sitekey, 'sameOrigin': True, 'siteUrl': self.referer, 'contextUrl': '/'.join(self.referer.split('/')[:3]), 'boundToDomain': True, 'stoken': None, 'captchaType': self.captchaType, 'captchaAction': self.captchaAction, 'captchaData': self.captchaData, 'token': self.sessionToken, 'pin': self.sessionPin, 'i18n': self._serverTexts(), 'tmpDir': GetTmpDir()}
        try:
            captcha = ensure_str(base64.b64encode(ensure_binary(json.dumps(captcha))))
        except Exception:
            printExc()

        while is_port_in_use(self.ip_address, self.port):
            self.port += 1

        cmd = GetPyScriptCmd('mye2iserver') + ' "%s" "%s" "%s"' % (captcha, self.ip_address, self.port)

        try:
            # scale=10 -> a 370x370 native PNG, comfortably above the qrcode widget's box
            # so Enigma2's scale="1" only ever downscales it, never blows it up.
            make_qr_png("http://%s:%s/%s" % (self.ip_address, self.port, ('?t=' + self.sessionToken) if self.sessionToken else ''), self._qrPath, scale=10, border=4)  # NOSONAR - LAN-only mye2iserver.py has no TLS support
            self["qrcode"].instance.setPixmap(LoadPixmap(self._qrPath))
            self["qrcode"].show()
        except Exception:
            printExc()

        self["console"].setText(_('Please Open site:\nhttp://{0}:{1}\nin a web browser with the MyE2i extension installed').format(self.ip_address, self.port))

        self.workconsole['console'] = eConsoleAppContainer()
        self.workconsole['close_conn'] = eConnectCallback(self.workconsole['console'].appClosed, self._scriptClosed)
        self.workconsole['stderr_conn'] = eConnectCallback(self.workconsole['console'].stderrAvail, self._scriptStderrAvail)
        self.workconsole['stdout_conn'] = eConnectCallback(self.workconsole['console'].stdoutAvail, self._scriptStdoutAvail)
        self.workconsole["console"].execute(E2PrioFix(cmd, 0))
        printDBG(">>> EXEC CMD [%s]" % cmd.replace(str(captcha), '<%d bytes of settings>' % len(str(captcha))))

    def onStart(self):
        self.onShown.remove(self.onStart)
        self.startExecution()

    def keyExit(self):
        self.close(self.result)

    def keyRed(self):
        self.close(self.result)

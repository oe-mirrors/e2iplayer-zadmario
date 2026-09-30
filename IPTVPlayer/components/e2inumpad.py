# -*- coding: utf-8 -*-
#
#  E2iPlayer numeric keypad
#
#  Small digits-only counterpart of E2iVirtualKeyBoard for fields that only
#  ever take a whole number (page jumps, ConfigInteger settings). Same call
#  convention as the full keyboard - (session, title=, text=,
#  additionalParams=) in, the entered text (or None on EXIT) out - so a
#  caller can switch between the two without touching its callback.
#
from Screens.Screen import Screen
from Components.ActionMap import NumberActionMap
from Components.Label import Label
from Components.Pixmap import Pixmap
from enigma import gRGB, getPrevAsciiCode
from Tools.LoadPixmap import LoadPixmap

###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc, GetIconDir
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.components.cover import Cover3
from Plugins.Extensions.IPTVPlayer.components.e2ivk import GetVKTier, _s, colorKeySkin
###################################################


class E2iNumericKeyBoard(Screen):
    # Like the full keyboard: everything in real pixels and every picture in
    # its real size per tier (icons/<TIER>/e2ivk) - older images can't scale
    # at runtime and know no "e" sizes / scale= in a skin.
    KEY_SIZE = {'HD': 50, 'FHD': 70, 'WQHD': 93}  # size of k.png
    BACK_ICON = {'HD': (34, 29), 'FHD': (48, 40), 'WQHD': (65, 55)}  # size of b.png
    KEY_FONT = {'HD': (20, 30), 'FHD': (25, 35), 'WQHD': (33, 47)}  # special keys, digits
    COLS = 3
    # without a limit a page number is the only thing typed here
    DEFAULT_MAX_DIGITS = 6

    COLOR_TEXT = 0xFFFFFF
    COLOR_TEXT_PRESET = 0x8A8F9C
    COLOR_RANGE = 0xB6B6B6
    COLOR_RANGE_BAD = 0xFF4040

    def __init__(self, session, title="", text="", additionalParams=None):
        self.session = session
        if additionalParams is None:
            additionalParams = {}
        self.minValue = additionalParams.get('min_value')
        self.maxValue = additionalParams.get('max_value')
        self.allowNegative = self.minValue is not None and self.minValue < 0

        # bottom row: the key left of 0 is +/- on a field that allows
        # negative values, Clear otherwise; row 5 is a full-width OK bar
        self.keyRows = [['1', '2', '3'], ['4', '5', '6'], ['7', '8', '9'], ['sign' if self.allowNegative else 'clear', '0', 'back'], ['ok']]

        self.tier, self.scale = GetVKTier()
        self.skin = self.prepareSkin()
        Screen.__init__(self, session)
        self.vkTitle = title
        self.setTitle(title)

        self["actions"] = NumberActionMap(["WizardActions", "DirectionActions", "ColorActions", "NumberActions", "KeyboardInputActions", "InputBoxActions", "InputAsciiActions"],
        {
            "ok": self.keyOK,
            "back": self.keyBack,
            "up": self.keyUp,
            "down": self.keyDown,
            "left": self.keyLeft,
            "right": self.keyRight,
            "green": self.accept,
            "blue": self.toggleSign,
            "deleteBackward": self.backspace,
            "gotAsciiCode": self.keyGotAscii,
            "1": self.keyNumberGlobal,
            "2": self.keyNumberGlobal,
            "3": self.keyNumberGlobal,
            "4": self.keyNumberGlobal,
            "5": self.keyNumberGlobal,
            "6": self.keyNumberGlobal,
            "7": self.keyNumberGlobal,
            "8": self.keyNumberGlobal,
            "9": self.keyNumberGlobal,
            "0": self.keyNumberGlobal,
        }, -2)

        self["text"] = Label("")
        self["range"] = Label("")
        for rowIdx, row in enumerate(self.keyRows):
            for colIdx, key in enumerate(row):
                name = self._keyName(rowIdx, colIdx)
                self[name] = Cover3()
                self[name + "_m"] = Cover3()
                self[name + "_l"] = Label(self._keyLabel(key))
        self["back_icon"] = Cover3()
        self["key_green"] = Label(_("Accept"))
        self["key_green_icon"] = Pixmap()
        if self.allowNegative:
            self["key_blue"] = Label("+/-")
            self["key_blue_icon"] = Pixmap()

        self.maxDigits = self.DEFAULT_MAX_DIGITS
        bounds = [abs(v) for v in (self.minValue, self.maxValue) if v is not None]
        if self.maxValue is not None and bounds:
            self.maxDigits = len(str(max(bounds)))

        # the preset value (e.g. the setting's current value) is shown
        # greyed out and the first digit typed replaces it, so a new value
        # never needs a round of backspaces first
        self.text = self._sanitize(text)
        self.preset = bool(self.text)

        # start on the OK bar: OK right away keeps the preset, digits come
        # from the remote's number keys anyway
        self.rowIdx = len(self.keyRows) - 1
        self.colIdx = 0

        self.onLayoutFinish.append(self.onStart)

    def prepareSkin(self):
        scale = self.scale
        key = self.KEY_SIZE[self.tier]
        fontSpecial, fontDigit = self.KEY_FONT[self.tier]
        gridW = self.COLS * key
        width = _s(440, scale)
        gridX = (width - gridW) // 2
        # colour keys on top like in the main window, the title in the
        # window's title bar
        keysY = _s(10, scale)
        inputX, inputY, inputW, inputH = _s(40, scale), keysY + _s(30, scale) + _s(14, scale), width - _s(80, scale), _s(50, scale)
        rangeY = inputY + inputH + _s(6, scale)
        gridY = rangeY + _s(34, scale)
        height = gridY + len(self.keyRows) * key + _s(16, scale)

        skinTab = ['<screen position="center,center" size="%d,%d" title="E2iPlayer">' % (width, height)]
        for slotIdx, color in enumerate(('green', 'blue') if self.allowNegative else ('green',)):
            skinTab.append(colorKeySkin(color, slotIdx, keysY, scale, pitch=200, labelW=150))

        def _addPixmapWidget(name, x, y, w, h, p):
            skinTab.append('<widget name="%s" zPosition="%d" position="%d,%d" size="%d,%d" transparent="1" alphatest="blend" />' % (name, p, x, y, w, h))


        # the number on a plain box (e.png is as wide as the full keyboard),
        # the allowed range below it
        skinTab.append('<eLabel position="%d,%d" size="%d,%d" backgroundColor="#404551" zPosition="1" />' % (inputX, inputY, inputW, inputH))
        skinTab.append('<widget name="text" position="%d,%d" size="%d,%d" zPosition="2" font="Regular;%d" halign="center" valign="center" noWrap="1" transparent="1" foregroundColor="#ffffff" backgroundColor="#404551" />' % (inputX + _s(10, scale), inputY, inputW - _s(20, scale), inputH, _s(32, scale)))
        skinTab.append('<widget name="range" position="%d,%d" size="%d,%d" zPosition="2" font="Regular;%d" halign="center" valign="center" noWrap="1" transparent="1" foregroundColor="#b6b6b6" backgroundColor="#00000000" />' % (inputX, rangeY, inputW, _s(26, scale), _s(18, scale)))

        for rowIdx, row in enumerate(self.keyRows):
            keyW = gridW // len(row)
            for colIdx, name in enumerate(row):
                wName = self._keyName(rowIdx, colIdx)
                x, y = gridX + colIdx * keyW, gridY + rowIdx * key
                _addPixmapWidget(wName, x, y, keyW, key, 1)
                _addPixmapWidget(wName + '_m', x, y, keyW, key, 5)
                # same colours as E2iVirtualKeyBoard's normal/special keys
                font, bg = (fontDigit, '#404551') if name.isdigit() else (fontSpecial, '#1688b2')
                skinTab.append('<widget name="%s_l" position="%d,%d" size="%d,%d" zPosition="3" font="Regular;%d" halign="center" valign="center" noWrap="1" transparent="1" foregroundColor="#ffffff" backgroundColor="%s" />' % (wName, x, y, keyW, key, font, bg))
                if name == 'back':
                    iconW, iconH = self.BACK_ICON[self.tier]
                    _addPixmapWidget('back_icon', x + (keyW - iconW) // 2, y + (key - iconH) // 2, iconW, iconH, 3)

        skinTab.append('</screen>')
        return '\n'.join(skinTab)

    def _keyName(self, rowIdx, colIdx):
        return "key_%d_%d" % (rowIdx, colIdx)

    def _keyLabel(self, key):
        # a digit is its own label, Backspace shows a picture
        return {'ok': "OK", 'clear': "C", 'sign': "+/-", 'back': ""}.get(key, key)

    def _sanitize(self, text):
        try:
            text = str(text).strip()
        except Exception:
            return ''
        negative = text.startswith('-') and self.allowNegative
        digits = ''.join([c for c in text if c.isdigit()])[:self.maxDigits]
        if not digits:
            return ''
        return ('-' if negative else '') + str(int(digits))

    def onStart(self):
        self.onLayoutFinish.remove(self.onStart)
        try:
            pix = {}
            # n3_s / n3_m: the OK bar, three keys wide
            for name in ('k', 'k_s', 'k_m', 'n3_s', 'n3_m', 'b'):
                pix[name] = LoadPixmap(GetIconDir('%s/e2ivk/%s.png' % (self.tier, name)))
            for rowIdx, row in enumerate(self.keyRows):
                for colIdx, key in enumerate(row):
                    name = self._keyName(rowIdx, colIdx)
                    if key == 'ok':
                        self[name].setPixmap(pix['n3_s'])
                        self[name + "_m"].setPixmap(pix['n3_m'])
                    else:
                        self[name].setPixmap(pix['k'] if key.isdigit() else pix['k_s'])
                        self[name + "_m"].setPixmap(pix['k_m'])
                    self[name + "_m"].hide()
            self["back_icon"].setPixmap(pix['b'])
        except Exception:
            printExc()
        self.moveMarker(-1, -1)
        self.updateText()

    # ---- display ----

    def moveMarker(self, oldRow, oldCol):
        if oldRow >= 0:
            self[self._keyName(oldRow, oldCol) + "_m"].hide()
        self[self._keyName(self.rowIdx, self.colIdx) + "_m"].show()

    def clamp(self, value):
        if self.minValue is not None and value < self.minValue:
            return self.minValue
        if self.maxValue is not None and value > self.maxValue:
            return self.maxValue
        return value

    def updateText(self):
        try:
            self["text"].instance.setForegroundColor(gRGB(self.COLOR_TEXT_PRESET if self.preset else self.COLOR_TEXT))
        except Exception:
            printExc()
        self["text"].setText(self.text)

        rangeText = ''
        if self.maxValue is not None:
            rangeText = "%d - %d" % (self.minValue if self.minValue is not None else 0, self.maxValue)
        bad = False
        if self.text not in ('', '-'):
            bad = self.clamp(int(self.text)) != int(self.text)
        try:
            self["range"].instance.setForegroundColor(gRGB(self.COLOR_RANGE_BAD if bad else self.COLOR_RANGE))
        except Exception:
            printExc()
        self["range"].setText(rangeText)

    # ---- editing ----

    def _takeOverPreset(self):
        if self.preset:
            self.preset = False
            self.text = ''

    def addDigit(self, digit):
        self._takeOverPreset()
        sign = '-' if self.text.startswith('-') else ''
        digits = self.text[len(sign):]
        if digits == '0':
            digits = ''
        if len(digits) >= self.maxDigits:
            return
        self.text = sign + digits + str(digit)
        self.updateText()

    def backspace(self):
        self.preset = False
        # "-3" becomes "-", so the sign survives retyping the digit
        self.text = self.text[:-1]
        self.updateText()

    def clear(self):
        self.preset = False
        self.text = ''
        self.updateText()

    def toggleSign(self):
        if not self.allowNegative:
            return
        self.preset = False
        if self.text.startswith('-'):
            self.text = self.text[1:]
        else:
            self.text = '-' + self.text
        self.updateText()

    def accept(self):
        if self.text in ('', '-'):
            self.close('')
            return
        value = self.clamp(int(self.text))
        printDBG("E2iNumericKeyBoard.accept [%s] -> [%d]" % (self.text, value))
        self.close(str(value))

    # ---- keys ----

    def keyNumberGlobal(self, number):
        self.addDigit(number)

    def keyGotAscii(self):
        try:
            char = getPrevAsciiCode()
        except Exception:
            printExc()
            return
        if 48 <= char <= 57:
            self.addDigit(char - 48)
        elif char == 45:
            self.toggleSign()
        elif char == 8:
            self.backspace()
        elif char in (10, 13):
            self.accept()

    def keyOK(self):
        key = self.keyRows[self.rowIdx][self.colIdx]
        if key.isdigit():
            self.addDigit(int(key))
        elif key == 'back':
            self.backspace()
        elif key == 'clear':
            self.clear()
        elif key == 'sign':
            self.toggleSign()
        elif key == 'ok':
            self.accept()

    def keyBack(self):
        self.close(None)

    def _moveTo(self, rowIdx, colIdx):
        oldRow, oldCol = self.rowIdx, self.colIdx
        self.rowIdx = rowIdx
        self.colIdx = min(colIdx, len(self.keyRows[rowIdx]) - 1)
        self.moveMarker(oldRow, oldCol)

    def keyUp(self):
        rowIdx = (self.rowIdx - 1) % len(self.keyRows)
        # leaving the one-key OK bar upwards lands on the middle key (0)
        colIdx = self.COLS // 2 if len(self.keyRows[self.rowIdx]) == 1 else self.colIdx
        self._moveTo(rowIdx, colIdx)

    def keyDown(self):
        rowIdx = (self.rowIdx + 1) % len(self.keyRows)
        colIdx = self.COLS // 2 if len(self.keyRows[self.rowIdx]) == 1 else self.colIdx
        self._moveTo(rowIdx, colIdx)

    def keyLeft(self):
        row = self.keyRows[self.rowIdx]
        self._moveTo(self.rowIdx, (self.colIdx - 1) % len(row))

    def keyRight(self):
        row = self.keyRows[self.rowIdx]
        self._moveTo(self.rowIdx, (self.colIdx + 1) % len(row))

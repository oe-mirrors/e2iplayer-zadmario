# -*- coding: utf-8 -*-
#
#  E2iPlayer On Screen Keyboard based on Windows keyboard layouts
#
#  $Id$
#
#
import codecs
import os
import re
from ast import literal_eval

from Screens.Screen import Screen
from Screens.MessageBox import MessageBox
from Components.ActionMap import NumberActionMap, ActionMap
from enigma import ePoint, eSize, gRGB, eListboxPythonMultiContent, gFont, RT_HALIGN_LEFT, RT_VALIGN_CENTER, getDesktop, getPrevAsciiCode
from Tools.LoadPixmap import LoadPixmap
from Tools.Directories import fileExists
from Components.Label import Label
from Components.Input import Input
from Components.config import config, configfile

###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.components.cover import Cover3
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc, GetDefaultLang, GetIconDir, GetE2iPlayerVKLayoutDir, CSearchHistoryHelper
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.components.iptvlist import IPTVListComponentBase
from Plugins.Extensions.IPTVPlayer.components.e2ivksuggestion import AutocompleteSearch
###################################################
from Plugins.Extensions.IPTVPlayer.p2p3.pVer import isPY2
###################################################

# Global, keyboard-wide search history shown inside the OSK itself (left/right
# arrow from the text field), independent of each host's own "Search history"
# menu item. Stored the same way as those (CSearchHistoryHelper), just under
# its own file so it doesn't mix with per-host entries.
gVKSearchHistory = CSearchHistoryHelper('e2ivk')


def toNative(text):
    # enigma2 widgets take UTF-8 byte strings on Python 2; the layout data
    # (.kle files, DEFAULT_VK_LAYOUT) is unicode
    if isPY2() and not isinstance(text, str):
        return text.encode('utf-8')
    return text


def GetVKTier():
    # (icon folder, scale) of the desktop: HD, FHD (1920) or WQHD (2560+).
    # Every picture exists per tier in its real size ("icons/<TIER>/..."),
    # nothing is scaled at runtime - older images can't do that.
    width = getDesktop(0).size().width()
    if width >= 2560:
        return 'WQHD', 2.0
    if width >= 1920:
        return 'FHD', 1.5
    return 'HD', 1.0


def GetVKFontSize(baseSize):
    # shared by E2iVKSelectionList and E2iVirtualKeyBoard.prepareSkin so the
    # osk_font_size_offset clamp rule only has to live in one place
    try:
        offset = int(config.plugins.iptvplayer.osk_font_size_offset.value)
    except Exception:
        offset = 0
    return max(8, baseSize + offset)


def _s(value, scale):
    # not round(): Python 2 and 3 round a half differently
    return int(value * scale + 0.5)


# real size of the flag pictures ("icons/<TIER>/e2ivk/flags")
FLAG_SIZE = {'HD': (40, 27), 'FHD': (60, 40), 'WQHD': (80, 53)}


# ---- colour key hints ---------------------------------------------------------
# like the main window (E2iPlayerWidget): the colour dot icons/<colour>.png
# (30x30) and a white label with a shadow; HD numbers times the tier's scale
COLOR_KEY_ICON = 30


def colorKeySkin(color, slotIdx, y, scale, pitch=260, labelW=210):
    x = _s(10 + slotIdx * pitch, scale)
    labelH = _s(30, scale)
    # the dot is a Pixmap widget "key_<colour>_icon" (the screen can hide it)
    return ('<widget name="key_%s_icon" pixmap="%s" position="%d,%d" size="%d,%d" zPosition="4" transparent="1" alphatest="on" />' % (color, GetIconDir('%s.png' % color), x, y + (labelH - COLOR_KEY_ICON) // 2, COLOR_KEY_ICON, COLOR_KEY_ICON) +
            '<widget name="key_%s" position="%d,%d" size="%d,%d" zPosition="5" valign="center" halign="left" backgroundColor="black" font="Regular;%d" transparent="1" foregroundColor="white" shadowColor="black" shadowOffset="-1,-1" />' % (color, x + COLOR_KEY_ICON + _s(5, scale), y, _s(labelW, scale), labelH, _s(20, scale)))


class E2iVKOption:
    # a row of the keyboard's Options menu / key help: text, value, icon
    def __init__(self, name, value=None, icon=None):
        self.name = name
        self.value = value
        self.icon = icon


def GetKeyHelpItem(label, description, icon=None):
    # "LABEL - description", both already translated: the button names are
    # translated on their own, not inside every description
    return E2iVKOption("%s - %s" % (label, description), None, icon)


class E2iInput(Input):
    def __init__(self, *args, **kwargs):
        self.e2iTimeoutCallback = None
        Input.__init__(self, *args, **kwargs)

    def timeout(self, *args, **kwargs):
        try:
            Input.timeout(self, *args, **kwargs)
        except Exception:
            printExc()
        if self.e2iTimeoutCallback:
            self.e2iTimeoutCallback()


class E2iVKSelectionList(IPTVListComponentBase):
    # text rows (search history, suggestions) or, with withRatioButton, the
    # layout list: radio button, flag, name

    def __init__(self, withRatioButton=True, applyFontOffset=True):
        IPTVListComponentBase.__init__(self)
        tier = GetVKTier()[0]
        # "/flags" per tier, next to the keyboard's own key art; flagSize and
        # dotSize are the real pixel sizes of those pictures
        self.flagsDir = '%s/e2ivk/flags' % tier
        self.flagSize = FLAG_SIZE[tier]
        # radio button and font have the same size
        fontSize = self.dotSize = {'HD': 16, 'FHD': 24, 'WQHD': 32}[tier]
        self.iconsFilesNames = {'on': '%s/radio_button_on.png' % tier, 'off': '%s/radio_button_off.png' % tier}
        # osk_font_size_offset sizes the on-screen keyboard itself;
        # applyFontOffset=False for the language picker popup
        if applyFontOffset:
            fontSize = GetVKFontSize(fontSize)
        # 14px above the font size; at FHD/WQHD the flag can be taller than
        # that, so whichever needs more room decides
        self.itemHeight = max(fontSize + 14, self.flagSize[1] + 3)
        self.l.setFont(0, gFont("Regular", fontSize))
        self.l.setItemHeight(self.itemHeight)
        self.dictPIX = {}
        # flag pixmaps by locale (e.g. 'de_DE'), loaded on first use;
        # flagNames = the files of flagsDir (see _getFlagName())
        self.flagPIX = {}
        self.flagNames = None
        self.withRatioButton = withRatioButton

    def _nullPIX(self):
        for key in self.iconsFilesNames:
            self.dictPIX[key] = None
        self.flagPIX = {}

    def onCreate(self):
        printDBG('--- onCreate ---')

        if self.withRatioButton:
            self._nullPIX()
            for key in self.dictPIX:
                try:
                    pixFile = self.iconsFilesNames.get(key, None)
                    if None is not pixFile:
                        self.dictPIX[key] = LoadPixmap(cached=True, path=GetIconDir(pixFile))
                except Exception:
                    printExc()

    def onDestroy(self):
        printDBG('--- onDestroy ---')
        if self.withRatioButton:
            self._nullPIX()

    def _getFlagName(self, locale):
        # flag file for a layout locale: the exact one, then without the
        # script part (sr_Cyrl-CS -> sr_CS), then a flag of the same country
        # (as_IN -> hi_IN = India), then of the same language, else
        # missing.png (historic scripts without a country)
        if self.flagNames is None:
            try:
                self.flagNames = sorted(os.listdir(GetIconDir(self.flagsDir)))
            except Exception:
                printExc()
                self.flagNames = []
        if locale + '.png' in self.flagNames:
            return locale + '.png'
        parts = re.split('[_-]', locale)
        if len(parts) > 2 and '%s_%s.png' % (parts[0], parts[-1]) in self.flagNames:
            return '%s_%s.png' % (parts[0], parts[-1])
        if len(parts) > 1:
            for name in self.flagNames:
                if name.endswith('_%s.png' % parts[-1]):
                    return name
        for name in self.flagNames:
            if name.startswith(parts[0] + '_'):
                return name
        return 'missing.png'

    def _getFlagPixmap(self, locale):
        if locale not in self.flagPIX:
            path = GetIconDir('%s/%s' % (self.flagsDir, self._getFlagName(locale)))
            try:
                self.flagPIX[locale] = LoadPixmap(cached=True, path=path)
            except Exception:
                printExc()
                self.flagPIX[locale] = None
        return self.flagPIX[locale]

    def buildEntry(self, item):
        res = [None]
        width = self.l.getItemSize().width()
        height = self.l.getItemSize().height()
        try:
            if self.withRatioButton and callable(getattr(item, "get", None)):
                if item['sel']:
                    sel_key = 'on'
                else:
                    sel_key = 'off'
                dotX = 3
                flagW, flagH = self.flagSize
                flagX = dotX + self.dotSize + 5
                textX = flagX + flagW + 8
                res.append((eListboxPythonMultiContent.TYPE_TEXT, textX, 0, width - textX, height, 0, RT_HALIGN_LEFT | RT_VALIGN_CENTER, item['val'][0]))
                dotIcon = self.dictPIX.get(sel_key, None)
                if dotIcon is not None:
                    res.append((eListboxPythonMultiContent.TYPE_PIXMAP_ALPHABLEND, dotX, (height - self.dotSize) // 2, self.dotSize, self.dotSize, dotIcon))
                flagPix = self._getFlagPixmap(item['val'][1])
                if flagPix is not None:
                    res.append((eListboxPythonMultiContent.TYPE_PIXMAP_ALPHABLEND, flagX, (height - flagH) // 2, flagW, flagH, flagPix))
            else:
                res.append((eListboxPythonMultiContent.TYPE_TEXT, 4, 0, width - 4, height, 0, RT_HALIGN_LEFT | RT_VALIGN_CENTER, item))
        except Exception:
            printExc()
        return res


class E2iVKLanguagePickerList(E2iVKSelectionList):
    # E2iVKPopup creates its list without arguments
    def __init__(self):
        E2iVKSelectionList.__init__(self, applyFontOffset=False)


class E2iVKOptionsList(IPTVListComponentBase):
    # icon + text rows of the Options menu and the key help (E2iVKOption)

    def __init__(self):
        IPTVListComponentBase.__init__(self)
        # osk_font_size_offset does not apply here - it sizes the keyboard
        # itself, not its popups
        tier = GetVKTier()[0]
        if tier == 'WQHD':
            self.iconW, self.iconH = (80, 51)
            fontSize = 38
            self.itemHeight = self.iconH + 32
        elif tier == 'FHD':
            self.iconW, self.iconH = (60, 38)
            fontSize = 28
            self.itemHeight = self.iconH + 24
        else:
            self.iconW, self.iconH = (40, 26)
            fontSize = 20
            self.itemHeight = self.iconH + 18
        self.l.setFont(0, gFont("Regular", fontSize))
        self.l.setItemHeight(self.itemHeight)

    def onCreate(self):
        pass

    def onDestroy(self):
        pass

    def buildEntry(self, item):
        width = self.l.getItemSize().width()
        height = self.l.getItemSize().height()
        res = [None]
        icon = getattr(item, 'icon', None)
        textX = self.iconW + 20 if icon is not None else 10
        res.append((eListboxPythonMultiContent.TYPE_TEXT, textX, 0, width - textX - 10, height, 0, RT_HALIGN_LEFT | RT_VALIGN_CENTER, item.name))
        if icon is not None:
            # in its own size, centred in the icon box (the pictures differ:
            # wide key icons, square menu icons)
            iconW, iconH = self.iconW, self.iconH
            try:
                size = icon.size()
                if size.width() > 0 and size.height() > 0:
                    iconW, iconH = size.width(), size.height()
            except Exception:
                pass
            res.append((eListboxPythonMultiContent.TYPE_PIXMAP_ALPHABLEND, 8 + (self.iconW - iconW) // 2, (height - iconH) // 2, iconW, iconH, icon))
        return res


class E2iVKPopup(Screen):
    # Small centred window with a title bar and a list: the keyboard's
    # language picker, Options menu and key help. Closes with the selected
    # row (OK) or None (EXIT). The list widget moves with UP/DOWN/LEFT/RIGHT
    # by itself (enigma2's ListboxActions).

    def __init__(self, session, title, options, listClass, currentIdx=0, width=600, maxRows=12, selectable=True):
        scale = GetVKTier()[1]
        self.options = options
        self.currentIdx = currentIdx
        self.selectable = selectable
        self.popupTitle = title
        popupList = listClass()
        rows = max(1, min(len(options), maxRows))
        listH = rows * popupList.itemHeight
        margin = _s(5, scale)
        width = _s(width, scale)
        # a plain image window like IPTVChoiceBoxWidget, the title in its
        # title bar
        self.skin = """<screen position="center,center" size="%d,%d" title="E2iPlayer">
            <widget name="popup_list" position="%d,%d" size="%d,%d" zPosition="2" scrollbarMode="showOnDemand" enableWrapAround="1" transparent="1" backgroundColor="#00000000" />
            </screen>""" % (width, listH + 2 * margin, margin, margin, width - 2 * margin, listH)
        Screen.__init__(self, session)
        self["popup_list"] = popupList
        self["actions"] = ActionMap(["WizardActions"],
        {
            "ok": self.keyOK,
            "back": self.keyBack,
        }, -1)
        self.onLayoutFinish.append(self.onStart)

    def onStart(self):
        self.onLayoutFinish.remove(self.onStart)
        self.setTitle(self.popupTitle)
        self["popup_list"].setList([(x,) for x in self.options])
        self["popup_list"].setSelectionState(self.selectable)
        try:
            self["popup_list"].moveToIndex(self.currentIdx)
        except Exception:
            printExc()

    def keyOK(self):
        if self.selectable:
            self.close(self["popup_list"].getCurrent())
        else:
            self.close(None)

    def keyBack(self):
        self.close(None)


class E2iVirtualKeyBoard(Screen):
    FOCUS_KEYBOARD = 0
    FOCUS_SUGGESTIONS = 2
    FOCUS_SEARCH_HISTORY = 3
    SK_NONE = 0
    SK_SHIFT = 1
    SK_CTRL = 2
    SK_ALT = 4
    SK_CAPSLOCK = 8
    # On-screen grid, 15 columns; a key spanning several columns repeats its
    # id. ISO layout with 48 character keys, like a real keyboard: 63 is the
    # key next to Enter (German #'), 44 the <> key next to the left Shift,
    # Caps Lock (30) a single key. The .kle files map every Windows layout
    # onto these ids by physical key.
    KEYIDMAP = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [16, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29],
        [30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 63, 42, 42],
        [43, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 55],
        [56, 56, 57, 58, 59, 59, 59, 59, 59, 59, 59, 59, 60, 61, 62],
    ]
    # every key id of the grid (0 = the input field)
    KEY_IDS = list(range(64))
    # keys that type characters (labelled from the layout)
    CHARACTER_KEYS = list(range(2, 15)) + list(range(17, 29)) + list(range(31, 42)) + [63] + list(range(44, 55)) + [59]
    LEFT_KEYS = [1, 16, 30, 43, 56]
    RIGHT_KEYS = [15, 29, 42, 55, 62]
    # keys with a picture instead of a text label: Backspace, Del, Left, Right
    ICON_KEYS = [15, 29, 61, 62]
    # (name, locale, Windows KLID) - every Windows keyboard layout
    # (kbdlayout.info); the layouts are in IPTVPlayer/vk/<KLID>.kle
    ALL_VK_LAYOUTS = [
        ('ADLaM', 'ff_Adlm-GN', '00140c00'),
        ('Albanian', 'sq_AL', '0000041c'),
        ('Arabic (101)', 'ar_SA', '00000401'),
        ('Arabic (101, Legacy)', 'ar_SA', '00030401'),
        ('Arabic (102)', 'ar_SA', '00010401'),
        ('Arabic (102) AZERTY', 'ar_SA', '00020401'),
        ('Armenian Eastern (Legacy)', 'hy_AM', '0000042b'),
        ('Armenian Phonetic', 'hy_AM', '0002042b'),
        ('Armenian Typewriter', 'hy_AM', '0003042b'),
        ('Armenian Western (Legacy)', 'hy_AM', '0001042b'),
        ('Assamese - INSCRIPT', 'as_IN', '0000044d'),
        ('Azerbaijani (Standard)', 'az_Latn-AZ', '0001042c'),
        ('Azerbaijani Cyrillic', 'az_Cyrl-AZ', '0000082c'),
        ('Azerbaijani Latin', 'az_Latn-AZ', '0000042c'),
        ('Bangla', 'bn_IN', '00000445'),
        ('Bangla - INSCRIPT', 'bn_IN', '00020445'),
        ('Bangla - INSCRIPT (Legacy)', 'bn_IN', '00010445'),
        ('Bashkir', 'ba_RU', '0000046d'),
        ('Belarusian', 'be_BY', '00000423'),
        ('Belgian (Comma)', 'fr_BE', '0001080c'),
        ('Belgian (Period)', 'nl_BE', '00000813'),
        ('Belgian French', 'fr_BE', '0000080c'),
        ('Bosnian (Cyrillic)', 'bs_Cyrl-BA', '0000201a'),
        ('Buginese', 'bug_Bugi-ID', '000b0c00'),
        ('Bulgarian', 'bg_BG', '00030402'),
        ('Bulgarian (Latin)', 'bg_BG', '00010402'),
        ('Bulgarian (Phonetic Traditional)', 'bg_BG', '00040402'),
        ('Bulgarian (Phonetic)', 'bg_BG', '00020402'),
        ('Bulgarian (Typewriter)', 'bg_BG', '00000402'),
        ('Canadian French', 'en_CA', '00001009'),
        ('Canadian French (Legacy)', 'fr_CA', '00000c0c'),
        ('Canadian Multilingual Standard', 'en_CA', '00011009'),
        ('Central Atlas Tamazight', 'tzm_Latn-DZ', '0000085f'),
        ('Central Kurdish', 'ku_Arab-IQ', '00000492'),
        ('Cherokee Nation', 'chr_Cher-US', '0000045c'),
        ('Cherokee Phonetic', 'chr_Cher-US', '0001045c'),
        ('Chinese (Simplified) - US', 'zh_CN', '00000804'),
        ('Chinese (Simplified, Singapore) - US', 'zh_SG', '00001004'),
        ('Chinese (Traditional) - US', 'zh_TW', '00000404'),
        ('Chinese (Traditional, Hong Kong S.A.R.) - US', 'zh_HK', '00000c04'),
        ('Chinese (Traditional, Macao S.A.R.) - US', 'zh_MO', '00001404'),
        ('Colemak', 'en_US', '00060409'),
        ('Croatian', 'hr_HR', '0000041a'),
        ('Czech', 'cs_CZ', '00000405'),
        ('Czech (QWERTY)', 'cs_CZ', '00010405'),
        ('Czech Programmers', 'cs_CZ', '00020405'),
        ('Danish', 'da_DK', '00000406'),
        ('Devanagari - INSCRIPT', 'hi_IN', '00000439'),
        ('Divehi Phonetic', 'dv_MV', '00000465'),
        ('Divehi Typewriter', 'dv_MV', '00010465'),
        ('Dutch', 'nl_NL', '00000413'),
        ('Dzongkha', 'dz_BT', '00000c51'),
        ('English (India)', 'en_IN', '00004009'),
        ('Estonian', 'et_EE', '00000425'),
        ('Faeroese', 'fo_FO', '00000438'),
        ('Finnish', 'fi_FI', '0000040b'),
        ('Finnish with Sami', 'se_SE', '0001083b'),
        ('French (Legacy, AZERTY)', 'fr_FR', '0000040c'),
        ('French (Standard, AZERTY)', 'fr_FR', '0001040c'),
        ('French (Standard, BÉPO)', 'fr_FR', '0002040c'),
        ('Futhark', 'gem_Runr', '00120c00'),
        ('Georgian (Ergonomic)', 'ka_GE', '00020437'),
        ('Georgian (Legacy)', 'ka_GE', '00000437'),
        ('Georgian (MES)', 'ka_GE', '00030437'),
        ('Georgian (Old Alphabets)', 'ka_GE', '00040437'),
        ('Georgian (QWERTY)', 'ka_GE', '00010437'),
        ('German', 'de_DE', '00000407'),
        ('German (IBM)', 'de_DE', '00010407'),
        ('German Extended (E1)', 'de_DE', '00020407'),
        ('German Extended (E2)', 'de_DE', '00030407'),
        ('Gothic', 'got_Goth', '000c0c00'),
        ('Greek', 'el_GR', '00000408'),
        ('Greek (220)', 'el_GR', '00010408'),
        ('Greek (220) Latin', 'el_GR', '00030408'),
        ('Greek (319)', 'el_GR', '00020408'),
        ('Greek (319) Latin', 'el_GR', '00040408'),
        ('Greek Latin', 'el_GR', '00050408'),
        ('Greek Polytonic', 'el_GR', '00060408'),
        ('Greenlandic', 'kl_GL', '0000046f'),
        ('Guarani', 'gn_PY', '00000474'),
        ('Gujarati', 'gu_IN', '00000447'),
        ('Hausa', 'ha_Latn-NG', '00000468'),
        ('Hawaiian', 'haw_US', '00000475'),
        ('Hebrew', 'he_IL', '0000040d'),
        ('Hebrew (Standard)', 'he_IL', '0002040d'),
        ('Hebrew (Standard, 2018)', 'he_IL', '0003040d'),
        ('Hindi Traditional', 'hi_IN', '00010439'),
        ('Hungarian', 'hu_HU', '0000040e'),
        ('Hungarian 101-key', 'hu_HU', '0001040e'),
        ('Icelandic', 'is_IS', '0000040f'),
        ('Igbo', 'ig_NG', '00000470'),
        ('Inuktitut - Latin', 'iu_Latn-CA', '0000085d'),
        ('Inuktitut - Naqittaut', 'iu_Cans-CA', '0001045d'),
        ('Inuktitut - Nattilik', 'iu_Cans-CA', '0002045d'),
        ('Irish', 'en_IE', '00001809'),
        ('Italian', 'it_IT', '00000410'),
        ('Italian (142)', 'it_IT', '00010410'),
        ('Japanese', 'ja_JP', '00000411'),
        ('Javanese', 'jv_Java-ID', '00110c00'),
        ('Kannada', 'kn_IN', '0000044b'),
        ('Kazakh', 'kk_KZ', '0000043f'),
        ('Khmer', 'km_KH', '00000453'),
        ('Khmer (NIDA)', 'km_KH', '00010453'),
        ('Korean', 'ko_KR', '00000412'),
        ('Kyrgyz Cyrillic', 'ky_KG', '00000440'),
        ('Lao', 'lo_LA', '00000454'),
        ('Latin American', 'es_MX', '0000080a'),
        ('Latvian', 'lv_LV', '00000426'),
        ('Latvian (QWERTY)', 'lv_LV', '00010426'),
        ('Latvian (Standard)', 'lv_LV', '00020426'),
        ('Lisu (Basic)', 'lis_Lisu-CN', '00070c00'),
        ('Lisu (Standard)', 'lis_Lisu-CN', '00080c00'),
        ('Lithuanian', 'lt_LT', '00010427'),
        ('Lithuanian IBM', 'lt_LT', '00000427'),
        ('Lithuanian Standard', 'lt_LT', '00020427'),
        ('Luxembourgish', 'lb_LU', '0000046e'),
        ('Macedonian', 'mk_MK', '0000042f'),
        ('Macedonian - Standard', 'mk_MK', '0001042f'),
        ('Malayalam', 'ml_IN', '0000044c'),
        ('Maltese 47-Key', 'mt_MT', '0000043a'),
        ('Maltese 48-Key', 'mt_MT', '0001043a'),
        ('Maori', 'mi_NZ', '00000481'),
        ('Marathi', 'mr_IN', '0000044e'),
        ('Mongolian (Mongolian Script)', 'mn_Mong-CN', '00000850'),
        ('Mongolian Cyrillic', 'mn_MN', '00000450'),
        ('Myanmar (Phonetic order)', 'my_MM', '00010c00'),
        ('Myanmar (Visual order)', 'my_MM', '00130c00'),
        ('Nepali', 'ne_NP', '00000461'),
        ('New Tai Lue', 'khb_Talu-CN', '00020c00'),
        ('Norwegian', 'nb_NO', '00000414'),
        ('Norwegian with Sami', 'se_NO', '0000043b'),
        ('NZ Aotearoa', 'en_NZ', '00001409'),
        ('N’Ko', 'nqo_GN', '00090c00'),
        ('Odia', 'or_IN', '00000448'),
        ('Ogham', 'sga_Ogam-IE', '00040c00'),
        ('Ol Chiki', 'sat_Olck-IN', '000d0c00'),
        ('Old Italic', 'ett_Ital-IT', '000f0c00'),
        ('Osage', 'osa_Osge-US', '00150c00'),
        ('Osmanya', 'so_Osma-SO', '000e0c00'),
        ('Pashto (Afghanistan)', 'ps_AF', '00000463'),
        ('Persian', 'fa_IR', '00000429'),
        ('Persian (Standard)', 'fa_IR', '00050429'),
        ('Phags-pa', 'mn_Phag-CN', '000a0c00'),
        ('Polish (214)', 'pl_PL', '00010415'),
        ('Polish (Programmers)', 'pl_PL', '00000415'),
        ('Portuguese', 'pt_PT', '00000816'),
        ('Portuguese (Brazil ABNT)', 'pt_BR', '00000416'),
        ('Portuguese (Brazil ABNT2)', 'pt_BR', '00010416'),
        ('Punjabi', 'pa_IN', '00000446'),
        ('Romanian (Legacy)', 'ro_RO', '00000418'),
        ('Romanian (Programmers)', 'ro_RO', '00020418'),
        ('Romanian (Standard)', 'ro_RO', '00010418'),
        ('Russian', 'ru_RU', '00000419'),
        ('Russian (Typewriter)', 'ru_RU', '00010419'),
        ('Russian - Mnemonic', 'ru_RU', '00020419'),
        ('Sakha', 'sah_RU', '00000485'),
        ('Sami Extended Finland-Sweden', 'se_SE', '0002083b'),
        ('Sami Extended Norway', 'se_NO', '0001043b'),
        ('Scottish Gaelic', 'en_IE', '00011809'),
        ('Serbian (Cyrillic)', 'sr_Cyrl-CS', '00000c1a'),
        ('Serbian (Latin)', 'sr_Latn-CS', '0000081a'),
        ('Sesotho sa Leboa', 'nso_ZA', '0000046c'),
        ('Setswana', 'tn_ZA', '00000432'),
        ('Sinhala', 'si_LK', '0000045b'),
        ('Sinhala - Wij 9', 'si_LK', '0001045b'),
        ('Slovak', 'sk_SK', '0000041b'),
        ('Slovak (QWERTY)', 'sk_SK', '0001041b'),
        ('Slovenian', 'sl_SI', '00000424'),
        ('Sora', 'srb_Sora-IN', '00100c00'),
        ('Sorbian Extended', 'hsb_DE', '0001042e'),
        ('Sorbian Standard', 'hsb_DE', '0002042e'),
        ('Sorbian Standard (Legacy)', 'hsb_DE', '0000042e'),
        ('Spanish', 'es_ES', '0000040a'),
        ('Spanish Variation', 'es_ES', '0001040a'),
        ('Swedish', 'sv_SE', '0000041d'),
        ('Swedish with Sami', 'se_SE', '0000083b'),
        ('Swiss French', 'fr_CH', '0000100c'),
        ('Swiss German', 'de_CH', '00000807'),
        ('Syriac', 'syr_SY', '0000045a'),
        ('Syriac Phonetic', 'syr_SY', '0001045a'),
        ('Tai Le', 'tdd_Tale-CN', '00030c00'),
        ('Tajik', 'tg_Cyrl-TJ', '00000428'),
        ('Tamil', 'ta_IN', '00000449'),
        ('Tamil 99', 'ta_IN', '00020449'),
        ('Tamil Anjal', 'ta_IN', '00030449'),
        ('Tatar', 'tt_RU', '00010444'),
        ('Tatar (Legacy)', 'tt_RU', '00000444'),
        ('Telugu', 'te_IN', '0000044a'),
        ('Thai Kedmanee', 'th_TH', '0000041e'),
        ('Thai Kedmanee (non-ShiftLock)', 'th_TH', '0002041e'),
        ('Thai Pattachote', 'th_TH', '0001041e'),
        ('Thai Pattachote (non-ShiftLock)', 'th_TH', '0003041e'),
        ('Tibetan (PRC)', 'bo_CN', '00000451'),
        ('Tibetan (PRC) - Updated', 'bo_CN', '00010451'),
        ('Tifinagh (Basic)', 'tzm_Tfng-MA', '0000105f'),
        ('Tifinagh (Extended)', 'tzm_Tfng-MA', '0001105f'),
        ('Traditional Mongolian (MNS)', 'mn_Mong-CN', '00020850'),
        ('Traditional Mongolian (Standard)', 'mn_Mong-CN', '00010850'),
        ('Turkish F', 'tr_TR', '0001041f'),
        ('Turkish Q', 'tr_TR', '0000041f'),
        ('Turkmen', 'tk_TM', '00000442'),
        ('Ukrainian', 'uk_UA', '00000422'),
        ('Ukrainian (Enhanced)', 'uk_UA', '00020422'),
        ('United Kingdom', 'en_GB', '00000809'),
        ('United Kingdom Extended', 'cy_GB', '00000452'),
        ('United States-Dvorak', 'en_US', '00010409'),
        ('United States-Dvorak for left hand', 'en_US', '00030409'),
        ('United States-Dvorak for right hand', 'en_US', '00040409'),
        ('United States-International', 'en_US', '00020409'),
        ('Urdu', 'ur_PK', '00000420'),
        ('US', 'en_US', '00000409'),
        ('US English Table for IBM Arabic 238_L', 'en_US', '00050409'),
        ('Uyghur', 'ug_CN', '00010480'),
        ('Uyghur (Legacy)', 'ug_CN', '00000480'),
        ('Uzbek Cyrillic', 'uz_Cyrl-UZ', '00000843'),
        ('Vietnamese', 'vi_VN', '0000042a'),
        ('Wolof', 'wo_SN', '00000488'),
        ('Yoruba', 'yo_NG', '0000046a'),
    ]
    # built-in layout (no file needed), same as vk/00020409.kle
    DEFAULT_VK_LAYOUT = {
        'id': u'00020409',
        'name': u'English (United States)',
        'desc': u'United States-International',
        'locale': u'en-US',
        'layout': {
            2: {0: u'`', 1: u'~', 8: u'`', 9: u'~'},
            3: {0: u'1', 1: u'!', 6: u'\xa1', 7: u'\xb9', 8: u'1', 9: u'!', 14: u'\xa1', 15: u'\xb9'},
            4: {0: u'2', 1: u'@', 6: u'\xb2', 8: u'2', 9: u'@', 14: u'\xb2'},
            5: {0: u'3', 1: u'#', 6: u'\xb3', 8: u'3', 9: u'#', 14: u'\xb3'},
            6: {0: u'4', 1: u'$', 6: u'\xa4', 7: u'\xa3', 8: u'4', 9: u'$', 14: u'\xa4', 15: u'\xa3'},
            7: {0: u'5', 1: u'%', 6: u'\u20ac', 8: u'5', 9: u'%', 14: u'\u20ac'},
            8: {0: u'6', 1: u'^', 6: u'\xbc', 8: u'6', 9: u'^', 14: u'\xbc'},
            9: {0: u'7', 1: u'&', 6: u'\xbd', 8: u'7', 9: u'&', 14: u'\xbd'},
            10: {0: u'8', 1: u'*', 6: u'\xbe', 8: u'8', 9: u'*', 14: u'\xbe'},
            11: {0: u'9', 1: u'(', 6: u'\u2018', 8: u'9', 9: u'(', 14: u'\u2018'},
            12: {0: u'0', 1: u')', 6: u'\u2019', 8: u'0', 9: u')', 14: u'\u2019'},
            13: {0: u'-', 1: u'_', 6: u'\xa5', 8: u'-', 9: u'_', 14: u'\xa5'},
            14: {0: u'=', 1: u'+', 6: u'\xd7', 7: u'\xf7', 8: u'=', 9: u'+', 14: u'\xd7', 15: u'\xf7'},
            17: {0: u'q', 1: u'Q', 6: u'\xe4', 7: u'\xc4', 8: u'Q', 9: u'q', 14: u'\xc4', 15: u'\xe4'},
            18: {0: u'w', 1: u'W', 6: u'\xe5', 7: u'\xc5', 8: u'W', 9: u'w', 14: u'\xc5', 15: u'\xe5'},
            19: {0: u'e', 1: u'E', 6: u'\xe9', 7: u'\xc9', 8: u'E', 9: u'e', 14: u'\xc9', 15: u'\xe9'},
            20: {0: u'r', 1: u'R', 6: u'\xae', 8: u'R', 9: u'r', 14: u'\xae'},
            21: {0: u't', 1: u'T', 6: u'\xfe', 7: u'\xde', 8: u'T', 9: u't', 14: u'\xde', 15: u'\xfe'},
            22: {0: u'y', 1: u'Y', 6: u'\xfc', 7: u'\xdc', 8: u'Y', 9: u'y', 14: u'\xdc', 15: u'\xfc'},
            23: {0: u'u', 1: u'U', 6: u'\xfa', 7: u'\xda', 8: u'U', 9: u'u', 14: u'\xda', 15: u'\xfa'},
            24: {0: u'i', 1: u'I', 6: u'\xed', 7: u'\xcd', 8: u'I', 9: u'i', 14: u'\xcd', 15: u'\xed'},
            25: {0: u'o', 1: u'O', 6: u'\xf3', 7: u'\xd3', 8: u'O', 9: u'o', 14: u'\xd3', 15: u'\xf3'},
            26: {0: u'p', 1: u'P', 6: u'\xf6', 7: u'\xd6', 8: u'P', 9: u'p', 14: u'\xd6', 15: u'\xf6'},
            27: {0: u'[', 1: u'{', 2: u'\x1b', 6: u'\xab', 8: u'[', 9: u'{', 10: u'\x1b', 14: u'\xab'},
            28: {0: u']', 1: u'}', 2: u'\x1d', 6: u'\xbb', 8: u']', 9: u'}', 10: u'\x1d', 14: u'\xbb'},
            31: {0: u'a', 1: u'A', 6: u'\xe1', 7: u'\xc1', 8: u'A', 9: u'a', 14: u'\xc1', 15: u'\xe1'},
            32: {0: u's', 1: u'S', 6: u'\xdf', 7: u'\xa7', 8: u'S', 9: u's', 14: u'\xdf', 15: u'\xa7'},
            33: {0: u'd', 1: u'D', 6: u'\xf0', 7: u'\xd0', 8: u'D', 9: u'd', 14: u'\xd0', 15: u'\xf0'},
            34: {0: u'f', 1: u'F', 8: u'F', 9: u'f'},
            35: {0: u'g', 1: u'G', 8: u'G', 9: u'g'},
            36: {0: u'h', 1: u'H', 8: u'H', 9: u'h'},
            37: {0: u'j', 1: u'J', 8: u'J', 9: u'j'},
            38: {0: u'k', 1: u'K', 8: u'K', 9: u'k'},
            39: {0: u'l', 1: u'L', 6: u'\xf8', 7: u'\xd8', 8: u'L', 9: u'l', 14: u'\xd8', 15: u'\xf8'},
            40: {0: u';', 1: u':', 6: u'\xb6', 7: u'\xb0', 8: u';', 9: u':', 14: u'\xb6', 15: u'\xb0'},
            41: {0: u"'", 1: u'"', 6: u'\xb4', 7: u'\xa8', 8: u"'", 9: u'"', 14: u'\xb4', 15: u'\xa8'},
            44: {0: u'\\', 1: u'|', 2: u'\x1c', 8: u'\\', 9: u'|', 10: u'\x1c'},
            45: {0: u'z', 1: u'Z', 6: u'\xe6', 7: u'\xc6', 8: u'Z', 9: u'z', 14: u'\xc6', 15: u'\xe6'},
            46: {0: u'x', 1: u'X', 8: u'X', 9: u'x'},
            47: {0: u'c', 1: u'C', 6: u'\xa9', 7: u'\xa2', 8: u'C', 9: u'c', 14: u'\xa9', 15: u'\xa2'},
            48: {0: u'v', 1: u'V', 8: u'V', 9: u'v'},
            49: {0: u'b', 1: u'B', 8: u'B', 9: u'b'},
            50: {0: u'n', 1: u'N', 6: u'\xf1', 7: u'\xd1', 8: u'N', 9: u'n', 14: u'\xd1', 15: u'\xf1'},
            51: {0: u'm', 1: u'M', 6: u'\xb5', 8: u'M', 9: u'm', 14: u'\xb5'},
            52: {0: u',', 1: u'<', 6: u'\xe7', 7: u'\xc7', 8: u',', 9: u'<', 14: u'\xc7', 15: u'\xe7'},
            53: {0: u'.', 1: u'>', 8: u'.', 9: u'>'},
            54: {0: u'/', 1: u'?', 6: u'\xbf', 8: u'/', 9: u'?', 14: u'\xbf'},
            59: {0: u' ', 1: u' ', 2: u' ', 8: u' ', 9: u' ', 10: u' '},
            63: {0: u'\\', 1: u'|', 2: u'\x1c', 6: u'\xac', 7: u'\xa6', 8: u'\\', 9: u'|', 10: u'\x1c', 14: u'\xac', 15: u'\xa6'},
        },
        'deadkeys': {
            u'"': {u' ': u'"', u'A': u'\xc4', u'E': u'\xcb', u'I': u'\xcf', u'O': u'\xd6', u'U': u'\xdc', u'a': u'\xe4', u'e': u'\xeb', u'i': u'\xef', u'o': u'\xf6', u'u': u'\xfc', u'y': u'\xff'},
            u"'": {u' ': u"'", u'A': u'\xc1', u'C': u'\xc7', u'E': u'\xc9', u'I': u'\xcd', u'O': u'\xd3', u'U': u'\xda', u'Y': u'\xdd', u'a': u'\xe1', u'c': u'\xe7', u'e': u'\xe9', u'i': u'\xed', u'o': u'\xf3', u'u': u'\xfa', u'y': u'\xfd'},
            u'^': {u' ': u'^', u'A': u'\xc2', u'E': u'\xca', u'I': u'\xce', u'O': u'\xd4', u'U': u'\xdb', u'a': u'\xe2', u'e': u'\xea', u'i': u'\xee', u'o': u'\xf4', u'u': u'\xfb'},
            u'`': {u' ': u'`', u'A': u'\xc0', u'E': u'\xc8', u'I': u'\xcc', u'O': u'\xd2', u'U': u'\xd9', u'a': u'\xe0', u'e': u'\xe8', u'i': u'\xec', u'o': u'\xf2', u'u': u'\xf9'},
            u'~': {u' ': u'~', u'A': u'\xc3', u'N': u'\xd1', u'O': u'\xd5', u'a': u'\xe3', u'n': u'\xf1', u'o': u'\xf5'},
        },
    }

    def _keyBox(self, keyId):
        # (x, y, w, h) of a key, from its cells in KEYIDMAP
        for rowIdx, row in enumerate(self.KEYIDMAP):
            if keyId in row:
                return self._gridX + self._gridBW * row.index(keyId), self._gridY + 10 + self._gridBH * rowIdx, self._gridBW * row.count(keyId), self._gridBH
        return None

    def prepareSkin(self):
        # full screen
        sz_w = getDesktop(0).size().width()
        sz_h = getDesktop(0).size().height()

        self.tier, scale = GetVKTier()

        # key size = the real size of the key art of the tier; the icon
        # boxes are the real sizes of vkey_left/right/delete.png and b.png
        if self.tier == 'WQHD':
            bw = bh = 93
            inputFontSize = GetVKFontSize(44)
            headerFontSize = GetVKFontSize(33)
            keyFont = GetVKFontSize(33)
            arrowIconW, arrowIconH = 65, 49
            deleteIconW, deleteIconH = 65, 55
        elif self.tier == 'FHD':
            bw = bh = 70
            inputFontSize = GetVKFontSize(33)
            headerFontSize = GetVKFontSize(25)
            keyFont = GetVKFontSize(25)
            arrowIconW, arrowIconH = 48, 36
            deleteIconW, deleteIconH = 48, 40
        else:
            bw = bh = 50
            inputFontSize = GetVKFontSize(26)
            headerFontSize = GetVKFontSize(20)
            keyFont = GetVKFontSize(20)
            arrowIconW, arrowIconH = 34, 26
            deleteIconW, deleteIconH = 34, 29
        # b.png is vkey_delete.png rotated by 180 degrees
        backspaceIconW, backspaceIconH = deleteIconW, deleteIconH
        textAlign = config.plugins.iptvplayer.osk_searchfield_align.value

        # key size and (below) grid origin, for _keyBox()
        self._gridBW, self._gridBH = bw, bh
        langIconW, langIconH, langIconOffsetY, langAreaW = self._getLanguageIconGeometry()

        x = (sz_w - 15 * bw) // 2
        y = sz_h - 7 * bh
        self._gridX, self._gridY = x, y

        bg_color = config.plugins.iptvplayer.osk_background_color.value
        bg_color = ' backgroundColor="%s" ' % bg_color if bg_color else ''

        skinTab = ["""<screen position="center,center" size="%d,%d" title="E2iPlayer virtual keyboard" %s >""" % (sz_w, sz_h, bg_color)]

        def _addPixmapWidget(name, x, y, w, h, p):
            skinTab.append('<widget name="%s" zPosition="%d" position="%d,%d" size="%d,%d" transparent="1" alphatest="blend" />' % (name, p, x, y, w, h))

        def _addMarker(name, x, y, w, h, p, color):
            skinTab.append('<widget name="%s" zPosition="%d" position="%d,%d" size="%d,%d" noWrap="1" font="Regular;2" valign="center" halign="center" foregroundColor="%s" backgroundColor="%s" />' % (name, p, x, y, w, h, color, color))

        def _addButton(name, x, y, w, h, p):
            _addPixmapWidget(name, x, y, w, h, p)
            if name in self.ICON_KEYS:
                return
            # the label's background colour is the one of the key art below
            # it: special keys (k_s / k2_s) or character keys
            color = '#1688b2' if name in [1, 16, 30, 42, 43, 55, 56, 57, 58, 60] else '#404551'
            align = 'center'
            if name == 56:
                # language key: the text starts right of the flag / globe
                align = 'left'
                x += langAreaW
                w -= langAreaW
            skinTab.append('<widget name="_%s" zPosition="%d" position="%d,%d" size="%d,%d" transparent="1" noWrap="1" font="Regular;%s" valign="center" halign="%s" foregroundColor="#ffffff" backgroundColor="%s" />' % (name, p + 2, x, y, w, h, keyFont, align, color))

        headerBoxH = bh - 7 * 2
        skinTab.append('<widget name="header" zPosition="%d" position="%d,%d" size="%d,%d"  transparent="1" noWrap="1" font="Regular;%s" valign="center" halign="left" foregroundColor="#ffffff" backgroundColor="#000000" />' % (2, x + 5, y - headerBoxH, 15 * bw - 10, headerBoxH, headerFontSize))
        skinTab.append('<widget name="text"   zPosition="%d" position="%d,%d" size="%d,%d"  transparent="1" noWrap="1" font="Regular;%s" valign="center" halign="%s" />' % (2, x + 5, y + 7, 15 * bw - 10, bh - 7 * 2, inputFontSize, textAlign))
        _addPixmapWidget(0, x, y, 15 * bw, bh, 1)
        _addPixmapWidget('e_m', 0, 0, 15 * bw, bh, 5)
        _addPixmapWidget('k_m', 0, 0, bw, bh, 5)
        _addPixmapWidget('k2_m', 0, 0, bw * 2, bh, 5)
        _addPixmapWidget('k3_m', 0, 0, bw * 8, bh, 5)

        _keyBox = self._keyBox

        # one button (pixmap + label) per key of the grid
        for keyId in self.KEY_IDS[1:]:
            _addButton(keyId, *_keyBox(keyId) + (1,))

        # icons centred on their keys: Backspace (15), Del (29), Left (61),
        # Right (62) - these keys have no text label
        for name, keyId, iconW, iconH in (('b', 15, backspaceIconW, backspaceIconH), ('vkey_delete', 29, deleteIconW, deleteIconH),
                                          ('vkey_left', 61, arrowIconW, arrowIconH), ('vkey_right', 62, arrowIconW, arrowIconH)):
            kx, ky, kw, kh = _keyBox(keyId)
            _addPixmapWidget(name, kx + (kw - iconW) // 2, ky + (kh - iconH) // 2, iconW, iconH, 3)

        kx, ky, kw, kh = _keyBox(56)
        _addPixmapWidget('l', kx + 10, ky + langIconOffsetY, langIconW, langIconH, 3)  # language icon (flag or globe)

        # colour bars under the keys the colour buttons press: Backspace
        # (RED), both Shift keys (BLUE), both Alt keys (YELLOW), Enter (GREEN)
        for name, keyId, color in (('m_0', 15, '#ed1c24'), ('m_1', 43, '#3f48cc'), ('m_2', 55, '#3f48cc'),
                                   ('m_3', 58, '#fff200'), ('m_4', 60, '#fff200'), ('m_5', 42, '#22b14c')):
            kx, ky, kw, kh = _keyBox(keyId)
            _addMarker(name, kx + 10, ky + (kh - 10), kw - 20, 3, 2, color)

        # Left list
        skinTab.append('<widget name="left_header" zPosition="2" position="%d,%d" size="%d,%d"  transparent="0" noWrap="1" font="Regular;%d" valign="center" halign="center" foregroundColor="#000000" backgroundColor="#ffffff" />' % (x - bw * 5 - 5, y - (bh - 7 * 2), bw * 5, headerBoxH, headerFontSize))
        skinTab.append('<widget name="left_list"   zPosition="1"  position="%d,%d" size="%d,%d" scrollbarMode="showOnDemand" transparent="0"  backgroundColor="#3f4450" enableWrapAround="1" />' % (x - bw * 5 - 5, y, bw * 5, 6 * bh + 10))

        # Right list
        if self.autocomplete:
            skinTab.append('<widget name="right_header" zPosition="2" position="%d,%d" size="%d,%d"  transparent="0" noWrap="1" font="Regular;%d" valign="center" halign="center" foregroundColor="#000000" backgroundColor="#ffffff" />' % (x + bw * 15 + 5, y - (bh - 7 * 2), bw * 5, headerBoxH, headerFontSize))
            skinTab.append('<widget name="right_list"   zPosition="1"  position="%d,%d" size="%d,%d" scrollbarMode="showOnDemand" transparent="0"  backgroundColor="#3f4450" enableWrapAround="1" />' % (x + bw * 15 + 5, y, bw * 5, 6 * bh + 10))

        skinTab.append('</screen>')
        return '\n'.join(skinTab)

    def __init__(self, session, title="", text="", additionalParams=None):
        self.session = session
        if additionalParams is None:
            additionalParams = {}

        # autocomplete engine
        self.autocomplete = additionalParams.get('autocomplete')
        self.isAutocompleteEnabled = False
        # only set when the panel above was already built with a provider;
        # lets _refreshSuggestionsProvider() swap it live when the "Default
        # suggestions provider" / "Allow host to override suggestions
        # provider" settings change without closing the keyboard
        self.suggestionsProviderFactory = additionalParams.get('resolve_suggestions_provider')

        # the text is a search entry: only then it is added to the search
        # history - a password or a file name typed for a setting is not
        self.isSearch = additionalParams.get('is_search', False)
        # the search history, read once per opening (showSearchHistory())
        self.searchHistory = []
        # (text, locale) of the last suggestions request
        self.suggestionsRequest = None

        self.skin = self.prepareSkin()

        Screen.__init__(self, session)
        self.setTitle(_("E2iPlayer virtual keyboard"))
        self.onLayoutFinish.append(self.setGraphics)
        self.onShown.append(self.onWindowShow)
        self.onClose.append(self.__onClose)

        # E2iPlayerVKActions (keymap.xml): MENU, INFO, PREVIOUS/NEXT, FAST
        # FORWARD/REWIND - own bindings, not every image has them in the
        # standard contexts used here
        self["actions"] = NumberActionMap(["WizardActions", "DirectionActions", "ColorActions", "E2iPlayerVKActions", "KeyboardInputActions", "InputBoxActions", "InputAsciiActions"],
        {
            "gotAsciiCode": self.keyGotAscii,
            "ok": self.keyOK,
            "ok_repeat": self.keyOK,
            "menu": self.keyMenu,
            "info": self.keyHelp,
            "back": self.keyBack,
            "left": self.keyLeft,
            "right": self.keyRight,
            "up": self.keyUp,
            "down": self.keyDown,
            "red": self.keyRed,
            "red_repeat": self.keyRed,
            "green": self.keyGreen,
            "yellow": self.keyYellow,
            "blue": self.keyBlue,
            "deleteBackward": self.keyRed,
            "deleteForward": self.keyDelete,
            "pageUp": self.cursorRight,
            "pageDown": self.cursorLeft,
            "vk_prevpanel": self.cyclePanelPrev,
            "vk_nextpanel": self.cyclePanelNext,
            "vk_space": self.keyFastForward,
            "vk_cleartext": self.keyRewind,
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

        # Left list
        self['left_header'] = Label(" ")
        self['left_list'] = E2iVKSelectionList()

        # Right list
        if self.autocomplete:
            self['right_header'] = Label(" ")
            self['right_list'] = E2iVKSelectionList(False)
        self.isSuggestionVisible = None

        self.graphics = {}
        # "icons/<TIER>/e2ivk": key art of the tier
        for key in ['l', 'b', 'e', 'e_m', 'k', 'k_m', 'k_s', 'k2_m', 'k2_s', 'k3', 'k3_m', 'vkey_left', 'vkey_right', 'vkey_delete']:
            self.graphics[key] = LoadPixmap(GetIconDir('%s/e2ivk/%s.png' % (self.tier, key)))
        # bottom bar: button hints and colour keys, "icons/<TIER>"
        for i in self.KEY_IDS:
            self[str(i)] = Cover3()

        for key in ['l', 'b', 'e_m', 'k_m', 'k2_m', 'k3_m', 'vkey_left', 'vkey_right', 'vkey_delete']:
            self[key] = Cover3()

        for i in self.KEY_IDS[1:]:
            if i not in self.ICON_KEYS:
                self['_%s' % i] = Label(" ")

        for m in range(6):
            self['m_%d' % m] = Label(" ")

        # key art: 'k' for character keys (default), 'k_s' / 'k2_s' for
        # single / double width special keys, 'k3' the space bar
        self.graphicsMap = {'0': 'e', '1': 'k_s', '15': 'k_s', '29': 'k_s', '30': 'k_s', '57': 'k_s', '58': 'k_s', '60': 'k_s', '61': 'k_s', '62': 'k_s', '59': 'k3',
                            '16': 'k2_s', '42': 'k2_s', '43': 'k2_s', '55': 'k2_s', '56': 'k2_s'}

        self.markerMap = {'0': 'e_m', '59': 'k3_m', '16': 'k2_m', '42': 'k2_m', '43': 'k2_m', '55': 'k2_m', '56': 'k2_m'}

        self.header = title if title else _('Enter the text')
        self.startText = text

        self["text"] = E2iInput(text="")
        self["header"] = Label(" ")

        self.colMax = len(self.KEYIDMAP[0])
        self.rowMax = len(self.KEYIDMAP)

        self.rowIdx = 0
        self.colIdx = 0

        self.colors = {'normal': gRGB(int('ffffff', 0x10)), 'selected': gRGB(int('39b54a', 0x10)), 'deadkey': gRGB(int('0275a0', 0x10)), 'ligature': gRGB(int('ed1c24', 0x10)), 'inactive': gRGB(int('979697', 0x10))}

        self.specialKeyState = self.SK_NONE
        self.currentVKLayout = self.DEFAULT_VK_LAYOUT
        self.selectedVKLayoutId = config.plugins.iptvplayer.osk_layout.value
        self.deadKey = u''
        self.focus = self.FOCUS_KEYBOARD
        # suggestions that arrived while the suggestions list had the focus
        self.pendingSuggestions = None

    @property
    def searchHistoryEnabled(self):
        # read live: the keyboard's own Settings screen can change it
        return config.plugins.iptvplayer.osk_allow_search_history.value

    def __onClose(self):
        self.onClose.remove(self.__onClose)
        self["text"].e2iTimeoutCallback = None
        if self.autocomplete:
            self.autocomplete.term()

        if self.selectedVKLayoutId != config.plugins.iptvplayer.osk_layout.value:
            config.plugins.iptvplayer.osk_layout.value = self.selectedVKLayoutId
            config.plugins.iptvplayer.osk_layout.save()
            configfile.save()

    def getKeyboardLayoutItem(self, vkLayoutId):
        for item in self.ALL_VK_LAYOUTS:
            if vkLayoutId == item[2]:
                return item
        return None

    def onWindowShow(self):
        self.onShown.remove(self.onWindowShow)
        # a couple of leading spaces keep the text off the box's left edge
        self["header"].setText("  " + self.header)

        # Left list
        self['left_list'].setSelectionState(False)
        self['left_header'].hide()
        self['left_list'].hide()
        self.showSearchHistory()

        # Right list
        if self.autocomplete:
            self['right_header'].setText(self.autocomplete.getProviderName())
            self['right_list'].setSelectionState(False)
            self['right_header'].hide()
            self['right_list'].hide()

        vkLayoutId = self.selectedVKLayoutId
        if vkLayoutId == '':
            e2Locale = GetDefaultLang(True)
            langMap = {'pl_PL': '00000415', 'en_EN': '00020409'}
            vkLayoutId = langMap.get(e2Locale, '')

            if vkLayoutId == '':
                # layouts of the locale, else of the language; the base
                # layout (KLID 0000xxxx - "US" for en_US, not "Colemak" or
                # "Dvorak", which sort before it) first
                candidates = [item[2] for item in self.ALL_VK_LAYOUTS if e2Locale == item[1]]
                if not candidates:
                    e2lang = GetDefaultLang() + '_'
                    candidates = [item[2] for item in self.ALL_VK_LAYOUTS if item[1].startswith(e2lang)]
                candidates.sort(key=lambda layoutId: not layoutId.startswith('0000'))
                if candidates:
                    vkLayoutId = candidates[0]

        if not self.getKeyboardLayoutItem(vkLayoutId):
            vkLayoutId = self.DEFAULT_VK_LAYOUT['id']

        if not self.loadKeyboardLayout(vkLayoutId):
            # the keys of the built-in layout instead of empty ones
            self.setVKLayout()
        self.isAutocompleteEnabled = self.autocomplete is not None
        self.setText(self.startText)

    def setText(self, text):
        text = toNative(text or '')
        self["text"].setText(text)
        self["text"].right()
        if isPY2():
            self["text"].currPos = len(text.decode('utf-8', 'ignore'))
        else:
            self["text"].currPos = len(text)
        self["text"].right()
        self.textUpdated()

    def setGraphics(self):
        self.onLayoutFinish.remove(self.setGraphics)
        self["text"].e2iTimeoutCallback = self.textUpdated

        for i in self.KEY_IDS:
            key = self.graphicsMap.get(str(i), 'k')
            self[str(i)].setPixmap(self.graphics[key])

        for key in ['e_m', 'k_m', 'k2_m', 'k3_m']:
            self[key].hide()
            self[key].setPixmap(self.graphics[key])

        self['b'].setPixmap(self.graphics['b'])
        # 'l' (language icon) is set from setVKLayout() - it depends on the
        # active layout and the osk_show_flags setting
        self['vkey_left'].setPixmap(self.graphics['vkey_left'])
        self['vkey_right'].setPixmap(self.graphics['vkey_right'])
        self['vkey_delete'].setPixmap(self.graphics['vkey_delete'])

        self.currentKeyId = self.KEYIDMAP[self.rowIdx][self.colIdx]
        self.moveKeyMarker(-1, self.currentKeyId)

        self.setSpecialKeyLabels()

    def setSpecialKeyLabels(self):
        self['_1'].setText('Esc')
        self['_16'].setText(_('Clear'))
        # 15 (Backspace), 29 (Del), 61 (Left), 62 (Right) show an icon
        self['_30'].setText('Caps')
        self['_42'].setText('Enter')
        self['_43'].setText('Shift')
        self['_55'].setText('Shift')
        self['_57'].setText('Ctrl')
        self['_58'].setText('Alt')
        self['_60'].setText('Alt')

    def handleArrowKey(self, dx=0, dy=0):
        oldKeyId = self.KEYIDMAP[self.rowIdx][self.colIdx]
        keyID = oldKeyId
        if dx != 0 and keyID == 0:
            return

        if dx != 0:  # left/right
            colIdx = self.colIdx
            while True:
                colIdx += dx
                if colIdx < 0:
                    colIdx = self.colMax - 1
                elif colIdx >= self.colMax:
                    colIdx = 0
                if keyID != self.KEYIDMAP[self.rowIdx][colIdx]:
                    self.colIdx = colIdx
                    break
        elif dy != 0:  # up/down
            rowIdx = self.rowIdx
            while True:
                rowIdx += dy
                if rowIdx < 0:
                    rowIdx = self.rowMax - 1
                elif rowIdx >= self.rowMax:
                    rowIdx = 0
                if keyID != self.KEYIDMAP[rowIdx][self.colIdx]:
                    self.rowIdx = rowIdx
                    break

        # center the cursor only when left/right
        if dx != 0:
            keyID = self.KEYIDMAP[self.rowIdx][self.colIdx]

            # find max
            maxKeyX = self.colIdx
            for idx in range(self.colIdx + 1, self.colMax):
                if keyID == self.KEYIDMAP[self.rowIdx][idx]:
                    maxKeyX = idx
                else:
                    break
            # find min
            minKeyX = self.colIdx
            for idx in range(self.colIdx - 1, -1, -1):
                if keyID == self.KEYIDMAP[self.rowIdx][idx]:
                    minKeyX = idx
                else:
                    break
            if maxKeyX - minKeyX > 2:
                self.colIdx = (maxKeyX + minKeyX) // 2

        self.currentKeyId = self.KEYIDMAP[self.rowIdx][self.colIdx]
        self.moveKeyMarker(oldKeyId, self.currentKeyId)

    def moveKeyMarker(self, oldKeyId, newKeyId):
        if oldKeyId == -1 and newKeyId == -1:
            for key in ['e_m', 'k_m', 'k2_m', 'k3_m']:
                self[key].hide()
            return

        if oldKeyId != -1:
            keyid = str(oldKeyId)
            marker = self.markerMap.get(keyid, 'k_m')
            self[marker].hide()

        if newKeyId != -1:
            keyid = str(newKeyId)
            marker = self.markerMap.get(keyid, 'k_m')
            self[marker].instance.move(ePoint(self[keyid].position[0], self[keyid].position[1]))
            self[marker].show()

    def handleKeyId(self, keyid):
        if keyid == 0:    # OK
            keyid = 42

        if keyid == 1:  # Escape
            if self.deadKey:
                self.deadKey = u''
                self.updateKeysLabels()
            else:
                self.close(None)
            return
        elif keyid == 15:  # Backspace
            self["text"].deleteBackward()
            self.textUpdated()
            return
        elif keyid == 29:  # Delete
            self["text"].delete()
            self.textUpdated()
            return
        elif keyid == 16:  # Clear
            self["text"].deleteAllChars()
            self["text"].update()
            self.textUpdated()
            return
        elif keyid == 56:  # Language
            self.switchToLanguageSelection()
            return
        elif keyid == 61:  # Left
            self["text"].left()
            return
        elif keyid == 62:  # Right
            self["text"].right()
            return
        elif keyid == 42:  # Enter
            try:
                # make sure that Input component return valid UTF-8 data
                if isPY2():
                    text = self["text"].getText().decode('UTF-8').encode('UTF-8')
                else:
                    text = self["text"].getText()
            except Exception:
                text = ''
                printExc()
            if text and self.isSearch and self.searchHistoryEnabled:
                try:
                    gVKSearchHistory.addHistoryItem(text)
                except Exception:
                    printExc()
            self.close(text)
            return
        elif keyid == 30:       # Caps Lock
            self.specialKeyState ^= self.SK_CAPSLOCK
            self.updateKeysLabels()
            self.updateSpecialKey([30], self.specialKeyState & self.SK_CAPSLOCK)
            return
        elif keyid in [43, 55]:  # Shift
            self.specialKeyState ^= self.SK_SHIFT
            self.updateKeysLabels()
            self.updateSpecialKey([43, 55], self.specialKeyState & self.SK_SHIFT)
            return
        elif keyid in [58, 60]:  # ALT
            self.specialKeyState ^= self.SK_ALT
            self.updateKeysLabels()
            self.updateSpecialKey([58, 60], self.specialKeyState & self.SK_ALT)
            return
        elif keyid == 57:       # CTRL
            self.specialKeyState ^= self.SK_CTRL
            self.updateKeysLabels()
            self.updateSpecialKey([57], self.specialKeyState & self.SK_CTRL)
            return
        else:
            updateKeysLabels = False
            ret = 0
            text = u''
            val = self.getKeyValue(keyid)

            if val:
                for special in [(self.SK_CTRL, [57]), (self.SK_ALT, [58, 60]), (self.SK_SHIFT, [43, 55])]:
                    if self.specialKeyState & special[0]:
                        self.specialKeyState ^= special[0]
                        self.updateSpecialKey(special[1], 0)
                        ret = None
                        updateKeysLabels = True

            if val:
                if self.deadKey:
                    if val in self.currentVKLayout['deadkeys'].get(self.deadKey, {}):
                        text = self.currentVKLayout['deadkeys'][self.deadKey][val]
                    else:
                        text = self.deadKey + val
                    self.deadKey = u''
                    updateKeysLabels = True
                elif val in self.currentVKLayout['deadkeys']:
                    self.deadKey = val
                    updateKeysLabels = True
                else:
                    text = val

                self.insertText(text)
                ret = None

            if updateKeysLabels:
                self.updateKeysLabels()
            return ret

    def loadKeyboardLayout(self, vkLayoutId):
        # the layouts come with the plugin (IPTVPlayer/vk/<KLID>.kle).
        # False (and an error message) when the layout can't be loaded - the
        # active layout stays as it is
        printDBG("loadKeyboardLayout vkLayoutId: %s" % vkLayoutId)
        if vkLayoutId == self.DEFAULT_VK_LAYOUT['id']:
            self.setVKLayout(self.DEFAULT_VK_LAYOUT)
            return True

        vkLayoutItem = self.getKeyboardLayoutItem(vkLayoutId)
        layoutName = vkLayoutItem[0] if vkLayoutItem else vkLayoutId
        filePath = GetE2iPlayerVKLayoutDir('%s.kle' % vkLayoutId)
        if fileExists(filePath):
            try:
                with open(filePath, 'rb') as f:
                    data = f.read()
                # UTF-8, as the files come with the plugin (half the size);
                # a UTF-16 file (with BOM), as other keyboards have them, is
                # read too
                if data[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
                    data = data.decode('utf-16')
                else:
                    data = data.decode('utf-8')
                data = literal_eval(data)
                if data['id'] != vkLayoutId:
                    raise Exception(_('Locale ID mismatched! %s <> %s') % (data['id'], vkLayoutId))
                self.setVKLayout(data)
                return True
            except Exception as e:
                printExc()
                errorMsg = _('Load of the Virtual Keyboard layout "%s" failed due to the following error: "%s"') % (layoutName, str(e))
        else:
            errorMsg = _('"%s" Virtual Keyboard layout not available.') % layoutName
        self.session.open(MessageBox, errorMsg, type=MessageBox.TYPE_ERROR, timeout=5)
        return False

    def setVKLayout(self, layout=None):
        if layout is not None:
            self.currentVKLayout = layout
        self.updateKeysLabels()
        self['_56'].setText(toNative(self.currentVKLayout['locale'].split('-', 1)[0].upper()))
        self['_56'].show()
        self._applyLanguageIconLayout()
        self.updateSuggestions()

    def _getCurrentLanguageIcon(self):
        # osk_show_flags off -> the plain globe icon. On -> the flag of the
        # active layout's locale, through left_list's flag lookup/cache
        # (keyed like the language picker, by ALL_VK_LAYOUTS' locale, e.g.
        # 'de_DE' - not currentVKLayout['locale'], which is 'de-DE')
        if not config.plugins.iptvplayer.osk_show_flags.value:
            return self.graphics['l']
        entry = self.getKeyboardLayoutItem(self.currentVKLayout.get('id'))
        flagPix = self['left_list']._getFlagPixmap(entry[1]) if entry else None
        return flagPix if flagPix is not None else self.graphics['l']

    def _getLanguageIconGeometry(self):
        # osk_show_flags on: box of a flag (the tier's real flag size); off:
        # the plain globe. Read live so the setting can restyle an open
        # keyboard via _applyLanguageIconLayout().
        if config.plugins.iptvplayer.osk_show_flags.value:
            langIconW, langIconH = FLAG_SIZE[self.tier]
        else:
            # real size of l.png
            langIconW = langIconH = 35 if self.tier == 'WQHD' else 26
        # centred in the key's height
        langIconOffsetY = (self._gridBH - langIconH) // 2
        # reserved width for the icon before key 56's "DE" label starts
        langAreaW = langIconW + 18
        return langIconW, langIconH, langIconOffsetY, langAreaW

    def _applyLanguageIconLayout(self):
        # live counterpart to the box prepareSkin() puts into the skin -
        # called after the keyboard's own Settings screen, so "Show flags"
        # needs no reopen
        langIconW, langIconH, langIconOffsetY, langAreaW = self._getLanguageIconGeometry()
        # box of the language key (56), as prepareSkin() lays it out
        keyX, keyY, keyW, keyH = self._keyBox(56)
        if self['l'].instance:
            self['l'].instance.resize(eSize(langIconW, langIconH))
            self['l'].instance.move(ePoint(keyX + 10, keyY + langIconOffsetY))

        if self['_56'].instance:
            self['_56'].instance.resize(eSize(keyW - langAreaW, keyH))
            self['_56'].instance.move(ePoint(keyX + langAreaW, keyY))

        self['l'].setPixmap(self._getCurrentLanguageIcon())

    def updateSpecialKey(self, keysidTab, state):
        if state:
            color = self.colors['selected']
        else:
            color = self.colors['normal']

        for keyid in keysidTab:
            self['_%s' % keyid].instance.setForegroundColor(color)

    def getKeyValue(self, keyid):
        state = self.specialKeyState
        # we treat both Alt keys as AltGr
        if self.specialKeyState & self.SK_ALT and not (self.specialKeyState & self.SK_CTRL):
            state ^= self.SK_CTRL
        key = self.currentVKLayout['layout'].get(keyid, {})
        if state in key:
            val = key[state]
        else:
            val = u''
        return val

    def updateNormalKeyLabel(self, keyid):

        val = self.getKeyValue(keyid)
        if not self.deadKey:
            if len(val) > 1:
                color = self.colors['ligature']
            elif val in self.currentVKLayout['deadkeys']:
                color = self.colors['deadkey']
            else:
                color = self.colors['normal']
        elif val in self.currentVKLayout['deadkeys'].get(self.deadKey, {}):
            val = self.currentVKLayout['deadkeys'][self.deadKey][val]
            color = self.colors['normal']
        else:
            color = self.colors['inactive']

        skinKey = self['_%s' % keyid]
        skinKey.instance.setForegroundColor(color)
        skinKey.setText(toNative(val))

    def updateKeysLabels(self):
        for keyid in self.CHARACTER_KEYS:
            self.updateNormalKeyLabel(keyid)

    def showSearchHistory(self):
        # reads the history file: when the keyboard opens and after the
        # Settings screen / "Delete search history"
        if self.searchHistoryEnabled:
            self.searchHistory = gVKSearchHistory.getHistoryList()
            self.refreshSearchHistory()
            self['left_list'].show()
            self['left_header'].setText(_('Search history'))
            self['left_header'].show()

    def refreshSearchHistory(self):
        # re-sort (not filter) the history on every keystroke: entries that
        # start with what is typed move to the top
        if not self.searchHistoryEnabled:
            return
        history = self.searchHistory
        word = self._getText().strip().lower()
        if word:
            matches, others = [], []
            for entry in history:
                (matches if entry.lower().startswith(word) else others).append(entry)
            history = matches + others
        self['left_list'].setList([(x,) for x in history])
        self['left_list'].moveToIndex(0)

    def hideLefList(self):
        self['left_header'].hide()
        self['left_list'].hide()
        self['left_list'].setList([])

    def switchToLanguageSelection(self):
        # a popup with all layouts (radio button, flag, name)
        selIdx = 0
        listValue = []
        for i, x in enumerate(self.ALL_VK_LAYOUTS):
            sel = self.currentVKLayout['id'] == x[2]
            if sel:
                selIdx = i
            listValue.append({'sel': sel, 'val': x})

        self.session.openWithCallback(self.languageSelectionClosed, E2iVKPopup, _('Select language'), listValue, E2iVKLanguagePickerList, currentIdx=selIdx, width=600, maxRows=13)

    def languageSelectionClosed(self, ret=None):
        if not ret:
            return
        try:
            vkLayoutId = ret['val'][2]
            # a layout that does not load is not remembered for the next time
            if self.loadKeyboardLayout(vkLayoutId):
                self.selectedVKLayoutId = vkLayoutId
        except Exception:
            printExc()

    def switchToKayboard(self):
        self.setFocus(self.FOCUS_KEYBOARD)
        self.moveKeyMarker(-1, self.currentKeyId)

    def switchToSuggestions(self):
        self.setFocus(self.FOCUS_SUGGESTIONS)
        self['right_list'].moveToIndex(0)
        self['right_list'].setSelectionState(True)

    def switchSearchHistory(self):
        self.setFocus(self.FOCUS_SEARCH_HISTORY)
        self['left_list'].moveToIndex(0)
        self['left_list'].setSelectionState(True)

    def setFocus(self, focus):
        self['text'].timeout()
        if self.focus != focus:
            if self.focus == self.FOCUS_KEYBOARD:
                self.moveKeyMarker(-1, -1)
            elif self.focus == self.FOCUS_SUGGESTIONS:
                self['right_list'].setSelectionState(False)
            elif self.focus == self.FOCUS_SEARCH_HISTORY:
                self['left_list'].setSelectionState(False)
            leftSuggestions = self.focus == self.FOCUS_SUGGESTIONS
            self.focus = focus
            if leftSuggestions and self.pendingSuggestions is not None:
                # an answer that came while the list had the focus
                self.setSuggestions(self.pendingSuggestions, None)

    def _pressKey(self, keyid):
        # a remote key that stands for a key of the grid - only while the
        # keyboard has the focus (0 = not handled)
        if self.focus != self.FOCUS_KEYBOARD:
            return 0
        self.handleKeyId(keyid)
        return None

    def keyRed(self):
        return self._pressKey(15)  # Backspace

    def keyGreen(self):
        self.handleKeyId(42)  # Enter, from every panel

    def keyYellow(self):
        return self._pressKey(60)  # AltGr

    def keyBlue(self):
        return self._pressKey(43)  # Shift

    def keyFastForward(self):
        return self._pressKey(59)  # Space

    def keyRewind(self):
        return self._pressKey(16)  # Clear entered text

    def keyDelete(self):
        return self._pressKey(29)

    def cursorRight(self):
        return self._pressKey(62)

    def cursorLeft(self):
        return self._pressKey(61)

    def _getAvailablePanels(self):
        panels = [self.FOCUS_KEYBOARD]
        if self.isSuggestionVisible:
            panels.append(self.FOCUS_SUGGESTIONS)
        if self.searchHistoryEnabled:
            panels.append(self.FOCUS_SEARCH_HISTORY)
        return panels

    def _switchToPanel(self, focus):
        if focus == self.FOCUS_KEYBOARD:
            self.switchToKayboard()
        elif focus == self.FOCUS_SUGGESTIONS:
            self.switchToSuggestions()
        elif focus == self.FOCUS_SEARCH_HISTORY:
            self.switchSearchHistory()

    def _cyclePanel(self, step):
        panels = self._getAvailablePanels()
        if len(panels) < 2:
            return 0
        idx = panels.index(self.focus) if self.focus in panels else 0
        self._switchToPanel(panels[(idx + step) % len(panels)])
        return None

    def cyclePanelNext(self):
        return self._cyclePanel(1)

    def cyclePanelPrev(self):
        return self._cyclePanel(-1)

    def keyMenu(self):
        if self.focus != self.FOCUS_KEYBOARD:
            return 0
        options = [E2iVKOption(_("Select language"), "LANGUAGE", LoadPixmap(GetIconDir('GlobItem.png')))]
        if self.searchHistoryEnabled:
            options.append(E2iVKOption(_("Delete search history"), "CLEAR_HISTORY", LoadPixmap(GetIconDir('SearchHistoryDeleteItem.png'))))
        options.append(E2iVKOption(_("Settings"), "SETTINGS", LoadPixmap(GetIconDir('SettingsItem.png'))))
        self.session.openWithCallback(self.menuCallback, E2iVKPopup, _("Options"), options, E2iVKOptionsList, width=460)

    def menuCallback(self, ret=None):
        if not isinstance(ret, E2iVKOption):
            return
        if ret.value == "LANGUAGE":
            self.switchToLanguageSelection()
        elif ret.value == "SETTINGS":
            from Plugins.Extensions.IPTVPlayer.components.iptvconfigmenu import E2iVKQuickSettings
            self.session.openWithCallback(self.settingsClosed, E2iVKQuickSettings)
        elif ret.value == "CLEAR_HISTORY":
            self.session.openWithCallback(self.clearSearchHistoryConfirmed, MessageBox, _('Are you sure you want to delete search history?'), type=MessageBox.TYPE_YESNO, default=True)

    def settingsClosed(self, ret=None):
        # restyles the language icon/text box for a live osk_show_flags
        # change instead of requiring the keyboard to be closed and reopened
        self._applyLanguageIconLayout()
        self._refreshSuggestionsProvider()
        if self.searchHistoryEnabled:
            self.showSearchHistory()
        else:
            self.hideLefList()

    def _refreshSuggestionsProvider(self):
        # right_list/right_header only exist when the keyboard was opened
        # with a provider (see prepareSkin()) - that layout can't be added
        # live. With one, the settings apply at once: another provider, or
        # none ("Show suggestions" off / provider "None") - the panel is
        # hidden then until a provider is chosen again
        if not self.suggestionsProviderFactory or not self.autocomplete:
            return
        try:
            newProvider = self.suggestionsProviderFactory()
        except Exception:
            printExc()
            return
        self.autocomplete.term()
        self['right_list'].setList([])
        self.pendingSuggestions = None
        self.suggestionsRequest = None
        if newProvider:
            self.autocomplete = AutocompleteSearch(newProvider)
            self['right_header'].setText(self.autocomplete.getProviderName())
            self.isAutocompleteEnabled = True
            self.updateSuggestions()
        else:
            self.setSuggestionVisible(False)
            self.isAutocompleteEnabled = False

    def clearSearchHistoryConfirmed(self, ret=None):
        if not ret:
            return
        err, msg = gVKSearchHistory.doRemove()
        if self.searchHistoryEnabled:
            self.showSearchHistory()
        else:
            self.hideLefList()
        self.session.open(MessageBox, msg, type=MessageBox.TYPE_ERROR if err else MessageBox.TYPE_INFO, timeout=5)

    def keyHelp(self):
        def icon(name):
            # the colour dots are the plugin's own icons/<colour>.png (30x30,
            # like in the main window), the key pictures exist per tier
            if name in ('red', 'green', 'yellow', 'blue'):
                return LoadPixmap(GetIconDir('%s.png' % name))
            return LoadPixmap(GetIconDir('%s/%s.png' % (self.tier, name)))

        options = [
            GetKeyHelpItem(_("OK"), _("type selected character / confirm selection"), icon('ok')),
            GetKeyHelpItem(_("GREEN"), _("Enter (confirm and close)"), icon('green')),
            GetKeyHelpItem(_("RED"), _("Backspace"), icon('red')),
            GetKeyHelpItem(_("YELLOW"), _("AltGr"), icon('yellow')),
            GetKeyHelpItem(_("BLUE"), _("Shift"), icon('blue')),
            GetKeyHelpItem(_("MENU"), _("Options (select language, clear search history, settings)"), icon('menu')),
            GetKeyHelpItem(_("PREVIOUS/NEXT"), _("switch between keyboard, suggestions and search history"), icon('key_prevnext')),
            E2iVKOption(_("LEFT/RIGHT at start/end of text - alternative way to switch panels"), None, icon('key_left_right_filled')),
            GetKeyHelpItem(_("PAGE UP/PAGE DOWN"), _("move cursor right/left"), icon('key_updown')),
            GetKeyHelpItem(_("FAST FORWARD"), _("insert space"), icon('fast_forward')),
            GetKeyHelpItem(_("REWIND"), _("delete entered text"), icon('rewind')),
            GetKeyHelpItem(_("0-9"), _("direct number input"), icon('key_0-9')),
        ]
        self.session.open(E2iVKPopup, _("Help"), options, E2iVKOptionsList, width=760, maxRows=len(options), selectable=False)

    def keyOK(self):
        if self.focus in (self.FOCUS_SUGGESTIONS, self.FOCUS_SEARCH_HISTORY):
            text = self['right_list' if self.focus == self.FOCUS_SUGGESTIONS else "left_list"].getCurrent()
            if text:
                self.setText(text)
                # belongs to the text before this one
                self.pendingSuggestions = None
            self.currentKeyId = 0
            self.rowIdx = 0
            self.colIdx = 7
            self.switchToKayboard()
        elif self.focus == self.FOCUS_KEYBOARD:
            self.handleKeyId(self.currentKeyId)
        else:
            return 0

    def keyBack(self):
        if self.focus == self.FOCUS_KEYBOARD:
            if self.deadKey:
                self.deadKey = u''
                self.updateKeysLabels()
            else:
                self.close(None)
        elif self.focus in (self.FOCUS_SUGGESTIONS, self.FOCUS_SEARCH_HISTORY):
            self.switchToKayboard()
        else:
            return 0

    def _moveVertical(self, dy):
        # on the key grid, or in the list that has the focus
        if self.focus == self.FOCUS_KEYBOARD:
            self.handleArrowKey(0, dy)
            return
        item = self['left_list' if self.focus == self.FOCUS_SEARCH_HISTORY else 'right_list']
        if item.instance is not None:
            item.instance.moveSelection(item.instance.moveUp if dy < 0 else item.instance.moveDown)

    def keyUp(self):
        self._moveVertical(-1)

    def keyDown(self):
        self._moveVertical(1)

    def keyLeft(self):
        if self.focus == self.FOCUS_SEARCH_HISTORY:
            if self.isSuggestionVisible:
                self.switchToSuggestions()
            else:
                self.switchToKayboard()
                if self.currentKeyId in self.LEFT_KEYS:
                    self.handleArrowKey(-1, 0)
        elif self.focus == self.FOCUS_SUGGESTIONS:
            self.switchToKayboard()
            if self.currentKeyId in self.LEFT_KEYS:
                self.handleArrowKey(-1, 0)
        elif self.focus == self.FOCUS_KEYBOARD:
            if self.currentKeyId in self.LEFT_KEYS or (self.currentKeyId == 0 and self['text'].currPos == 0):
                if self.searchHistoryEnabled:
                    self.switchSearchHistory()
                    return
                elif self.isSuggestionVisible:
                    self.switchToSuggestions()
                    return

            if self.currentKeyId == 0:
                self["text"].left()
            else:
                self.handleArrowKey(-1, 0)
        else:
            return 0

    def keyRight(self):
        if self.focus == self.FOCUS_SEARCH_HISTORY:
            self.switchToKayboard()
            if self.currentKeyId in self.RIGHT_KEYS:
                self.handleArrowKey(1, 0)
        elif self.focus == self.FOCUS_SUGGESTIONS:
            if self.searchHistoryEnabled:
                self.switchSearchHistory()
            else:
                self.switchToKayboard()
                if self.currentKeyId in self.RIGHT_KEYS:
                    self.handleArrowKey(1, 0)
        elif self.focus == self.FOCUS_KEYBOARD:
            # the length of the entered text, not of the displayed one: that
            # has an extra cursor cell at its end (a space or NBSP)
            if self.currentKeyId in self.RIGHT_KEYS or (self.currentKeyId == 0 and self['text'].currPos >= self._getTextLength()):
                if self.isSuggestionVisible:
                    self.switchToSuggestions()
                    return
                elif self.searchHistoryEnabled:
                    self.switchSearchHistory()
                    return

            if self.currentKeyId == 0:
                self["text"].right()
            else:
                self.handleArrowKey(1, 0)
        else:
            return 0

    def _isTextFieldActive(self):
        # the marker is on the text field - not merely left there while a
        # list has the focus
        return self.focus == self.FOCUS_KEYBOARD and self.currentKeyId == 0

    def keyNumberGlobal(self, number):
        if self._isTextFieldActive():
            try:
                self["text"].number(number)
            except Exception:
                printExc()

    def keyGotAscii(self):
        if self._isTextFieldActive():
            try:
                self["text"].handleAscii(getPrevAsciiCode())
            except Exception:
                printExc()

    def setSuggestionVisible(self, visible):
        if self.isAutocompleteEnabled and self.isSuggestionVisible != visible:
            if visible:
                self['right_header'].show()
                self['right_list'].show()
            else:
                self['right_header'].hide()
                self['right_list'].hide()

            self.isSuggestionVisible = visible

    def insertText(self, text):
        for letter in text:
            try:
                self["text"].insertChar(letter, self["text"].currPos, False, True)
                # right(), not innerRight()/innerright(): the cursor-advance
                # helper is named differently per image, right() is the same
                # move under a name all share and calls update() itself
                self["text"].right()
            except Exception:
                printExc()
        self.textUpdated()

    def textUpdated(self):
        self.updateSuggestions()
        self.refreshSearchHistory()

    def _getText(self):
        # the entered text as a native string (Input.text is what is
        # displayed: it has an extra cursor cell at its end, so it is never
        # empty)
        try:
            return self["text"].getText()
        except Exception:
            printExc()
            return ''

    def _getTextLength(self):
        # in characters, like Input.currPos
        text = self._getText()
        if isPY2():
            try:
                return len(text.decode('utf-8', 'ignore'))
            except Exception:
                printExc()
        return len(text)

    def updateSuggestions(self):
        if not self.isAutocompleteEnabled:
            return
        text = self._getText()
        request = (text, toNative(self.currentVKLayout['locale']))
        if request == self.suggestionsRequest:
            # asked already - the cursor moved or the focus changed, the
            # text did not
            return
        self.suggestionsRequest = request
        if not text:
            self.pendingSuggestions = None
            self.setSuggestionVisible(False)
            self['right_list'].setList([])
        else:
            self.autocomplete.start(self.setSuggestions)
            self.autocomplete.set(*request)

    def setSuggestions(self, suggestions, stamp):
        if self.focus == self.FOCUS_SUGGESTIONS:
            # we would not want to modify list when user is under selection
            # item from it - shown when the focus leaves the list (setFocus())
            self.pendingSuggestions = suggestions
            return
        self.pendingSuggestions = None
        if self._getText():
            if suggestions:
                self['right_list'].setList([(x,) for x in suggestions])
            self.setSuggestionVisible(bool(suggestions))
        else:
            printDBG("setSuggestions ignored")

# -*- coding: utf-8 -*-
###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.components.ihost import ArticleContent
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc
###################################################

###################################################
# FOREIGN import
###################################################
from Screens.Screen import Screen
from Components.ActionMap import ActionMap
from Components.Label import Label
from Components.ScrollLabel import ScrollLabel
from enigma import getDesktop
###################################################


class ArticleView(Screen):
    sz_w = getDesktop(0).size().width() - 200
    sz_h = getDesktop(0).size().height() - 200

    skin = """
        <screen position="center,center" size="%d,%d" title="Info..." >
            <widget name="text" position="10,10" size="%d,%d" font="Regular;24" />
        </screen>""" % (sz_w, sz_h, sz_w - 20, sz_h - 20)

    def __init__(self, session, artItem, addParams=None):
        printDBG("ArticleView.__init__ -------------------------------")
        self.session = session
        # blue = "Trailer" (a film / series row of the list): closes with 'trailer', the list looks for it
        self.withTrailer = bool((addParams or {}).get('trailer'))
        if self.withTrailer:
            self.skin = """
        <screen position="center,center" size="%d,%d" title="Info..." >
            <widget name="text" position="10,10" size="%d,%d" font="Regular;24" />
            <widget name="key_blue" position="10,%d" size="%d,32" font="Regular;24" halign="right" valign="center" transparent="1" foregroundColor="blue" />
        </screen>""" % (self.sz_w, self.sz_h, self.sz_w - 20, self.sz_h - 60, self.sz_h - 42, self.sz_w - 20)
        Screen.__init__(self, session)
        if self.withTrailer:
            self["key_blue"] = Label(_("Trailer"))
            self["trailerActions"] = ActionMap(['ColorActions'], {"blue": self.trailer}, -1)

        self["text"] = ScrollLabel("")
        self["actions"] = ActionMap(["WizardActions", "DirectionActions"],
        {
            "ok": self.cancel,
            "back": self.cancel,
            "up": self["text"].pageUp,
            "down": self["text"].pageDown
        }, -1)

        self.title = artItem.title
        self.textContent = artItem.text

        self.onClose.append(self.__onClose)
        self.onShown.append(self.updateTitle)
        self.onLayoutFinish.append(self.startRun) # dont start before gui is finished

    def __del__(self):
        printDBG("ArticleView.__del__ -------------------------------")

    def __onClose(self):
        printDBG("ArticleView.__onClose -----------------------------")
        self.onClose.remove(self.__onClose)
        self.onShown.remove(self.updateTitle)
        self.onLayoutFinish.remove(self.startRun)

    def updateTitle(self):
        self.setTitle(self.title)

    def startRun(self):
        self["text"].setText(self.textContent)

    def cancel(self):
        self.close()

    def trailer(self):
        self.close('trailer')

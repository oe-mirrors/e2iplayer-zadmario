# -*- coding: utf-8 -*-

###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, GetCookieDir
from Plugins.Extensions.IPTVPlayer.libs.pCommon import common
from Plugins.Extensions.IPTVPlayer.libs.urlparser import urlparser
from Plugins.Extensions.IPTVPlayer.libs.urlparserhelper import getDirectM3U8Playlist
from Plugins.Extensions.IPTVPlayer.components.ihost import CBaseHostClass
###################################################

###################################################
# FOREIGN import
###################################################
from Components.config import config, ConfigSelection, getConfigListEntry
############################################

###################################################
# Config options for HOST
###################################################
config.plugins.iptvplayer.skylinewebcams_lang = ConfigSelection(default="en", choices=[("en", "en"), ("it", "it"), ("es", "es"), ("de", "de"), ("fr", "fr"), ("pl", "pl"),
                                                                                           ("el", "el"), ("hr", "hr"), ("sl", "sl"), ("ru", "ru"), ("zh", "zh")])


def GetConfigList():
    optionList = []
    optionList.append(getConfigListEntry(_("Language:"), config.plugins.iptvplayer.skylinewebcams_lang))
    return optionList

###################################################


class WkylinewebcamsComApi:
    MAIN_URL = 'https://www.skylinewebcams.com/'

    def __init__(self):
        self.COOKIE_FILE = GetCookieDir('skylinewebcamscom.cookie')
        self.cm = common()
        self.up = urlparser()
        self.http_params = {'save_cookie': True, 'load_cookie': True, 'cookiefile': self.COOKIE_FILE}
        self.lang = config.plugins.iptvplayer.skylinewebcams_lang.value

    def getFullUrl(self, url):
        if url == '':
            return ''
        if url.startswith('//'):
            return 'https:' + url
        if url.startswith('http'):
            return url
        elif url.startswith('/'):
            url = url[1:]
        return self.MAIN_URL + url

    def cleanHtmlStr(self, str):
        return CBaseHostClass.cleanHtmlStr(str)

    def getPage(self, url):
        return self.cm.getPage(url, self.http_params)

    def getMainMenu(self, cItem):
        # site layout since 2026: /<lang>/categories.html holds TOP, New and the categories as tiles,
        # /<lang>/webcam.html the countries grouped per continent (<h2 class="menu-nm"> + <div class="menu-list">)
        printDBG("WkylinewebcamsCom.getMainMenu")
        retList = []
        sts, data = self.getPage(self.getFullUrl('/%s/categories.html' % self.lang))
        if sts:
            for item in self.cm.ph.getAllItemsBeetwenMarkers(data, '<a class="cam cam-link"', '</a>'):
                url = self.cm.ph.getSearchGroups(item, '''href="([^"]+?)"''')[0]
                title = self.cleanHtmlStr(self.cm.ph.getDataBeetwenNodes(item, ('<span', '>', 'cam-title'), ('</span', '>'), False)[1])
                if url == '' or title == '':
                    continue
                icon = self.cm.ph.getSearchGroups(item, '''<img[^>]+?src="([^"]+?)"''')[0]
                desc = self.cleanHtmlStr(self.cm.ph.getDataBeetwenNodes(item, ('<span', '>', 'meta'), ('</span', '>'), False)[1])
                params = dict(cItem)
                params.update({'title': title, 'url': self.getFullUrl(url), 'icon': self.getFullUrl(icon), 'desc': desc, 'cat': 'list_cams'})
                retList.append(params)

        countriesUrl = self.getFullUrl('/%s/webcam.html' % self.lang)
        sts, data = self.getPage(countriesUrl)
        if sts:
            for idx, name in enumerate(self.cm.ph.getAllItemsBeetwenNodes(data, ('<h2', '>', 'menu-nm'), ('</h2', '>'), False)):
                title = self.cleanHtmlStr(name)
                if title == '':
                    continue
                params = dict(cItem)
                params.update({'title': title.title(), 'url': countriesUrl, 'cat': 'list_continent', 'idx': idx})
                retList.append(params)
        return retList

    def listContinent(self, cItem):
        printDBG("WkylinewebcamsCom.listContinent idx[%s]" % cItem.get('idx'))
        retList = []
        sts, data = self.getPage(cItem['url'])
        if not sts:
            return retList
        lists = self.cm.ph.getAllItemsBeetwenNodes(data, ('<div', '>', 'menu-list'), ('</div', '>'), False)
        idx = cItem.get('idx', 0)
        if idx >= len(lists):
            return retList
        for item in self.cm.ph.getAllItemsBeetwenMarkers(lists[idx], '<a ', '</a>'):
            url = self.cm.ph.getSearchGroups(item, '''href="([^"]+?)"''')[0]
            title = self.cleanHtmlStr(item)
            if url == '' or title == '':
                continue
            params = dict(cItem)
            params.update({'title': title, 'url': self.getFullUrl(url), 'cat': 'list_cams'})
            retList.append(params)
        return retList

    def listCams(self, cItem):
        printDBG("WkylinewebcamsCom.listCams url[%s]" % cItem['url'])
        retList = []
        sts, data = self.getPage(cItem['url'])
        if not sts:
            return retList

        # country / region pages: <nav class="chips"> with the sub-regions (and a "back" chip to the parent)
        chips = self.cm.ph.getDataBeetwenNodes(data, ('<nav', '>', 'chips'), ('</nav', '>'), False)[1]
        for item in self.cm.ph.getAllItemsBeetwenMarkers(chips, '<a ', '</a>'):
            if 'class="back"' in item:
                continue
            url = self.cm.ph.getSearchGroups(item, '''href="([^"]+?)"''')[0]
            title = self.cleanHtmlStr(item)
            if url == '' or title == '':
                continue
            params = dict(cItem)
            params.update({'title': title, 'url': self.getFullUrl(url), 'desc': '', 'cat': 'list_cams'})
            retList.append(params)

        seen = set()
        for item in data.split('<div class="cam">')[1:]:
            url = self.cm.ph.getSearchGroups(item, '''<a[^>]+?class="cam-title"[^>]+?href="([^"]+?)"''')[0]
            if url == '':
                url = self.cm.ph.getSearchGroups(item, '''href="([^"]*?/webcam/[^"]+?\\.html)"''')[0]
            if url == '' or url in seen:
                continue
            seen.add(url)
            title = self.cleanHtmlStr(self.cm.ph.getDataBeetwenNodes(item, ('<a', '>', 'cam-title'), ('</a', '>'), False)[1])
            if title == '':
                title = self.cleanHtmlStr(self.cm.ph.getSearchGroups(item, '''alt="([^"]+?)"''')[0])
            icon = self.cm.ph.getSearchGroups(item, '''<img[^>]+?src="([^"]+?)"''')[0]
            desc = []
            badge = self.cleanHtmlStr(self.cm.ph.getDataBeetwenNodes(item, ('<span', '>', 'badge'), ('</span', '>'), False)[1])
            if badge:
                desc.append(badge)
            meta = self.cm.ph.getDataBeetwenNodes(item, ('<div', '>', 'meta'), ('</div', '>'), False)[1]
            meta = self.cleanHtmlStr(meta.replace('</a><a', '</a> - <a'))  # "<a>Country</a><a>City</a>"
            if meta:
                desc.append(meta)
            params = dict(cItem)
            params.update({'title': title, 'url': self.getFullUrl(url), 'icon': self.getFullUrl(icon), 'desc': '[/br]'.join(desc), 'type': 'video'})
            retList.append(params)
        printDBG("WkylinewebcamsCom.listCams found %d items" % len(retList))
        return retList

    def getChannelsList(self, cItem):
        printDBG("WkylinewebcamsCom.getChannelsList")
        cat = cItem.get('cat', None)
        self.lang = config.plugins.iptvplayer.skylinewebcams_lang.value
        if None is cat:
            return self.getMainMenu(cItem)
        elif 'list_continent' == cat:
            return self.listContinent(cItem)
        elif 'list_cams' == cat:
            return self.listCams(cItem)
        return []

    def getVideoLink(self, cItem):
        printDBG("WkylinewebcamsCom.getVideoLink")
        urlsTab = []
        sts, data = self.getPage(cItem['url'])
        if not sts:
            return urlsTab
        if not self.cm.ph.getSearchGroups(data, '''(youtube.com/iframe_api)''', 1, True)[0]:
            # Clappr setup: source: "livee.m3u8?a=<token>" -> https://hd-auth.skylinewebcams.com/live.m3u8?a=<token>
            # the token belongs to the session and serves the cam whose page was opened last, so the page
            # has to be fetched right before playback (as done here)
            url = self.cm.ph.getSearchGroups(data, '''source:\\s*['"]([^"^']+?m3u8[^"^']*?)["']''', 1, True)[0]
            if url == '':
                # without the player setup: any quoted live(e).m3u8 or hd-auth playlist url of the page
                url = self.cm.ph.getSearchGroups(data, '''["']((?:livee?\\.m3u8|[^"']*?hd-auth\\.skylinewebcams\\.com/[^"']*?\\.m3u8)[^"']*?)["']''', 1, True)[0]
            if url.startswith('//'):
                url = 'https:' + url
            if url.startswith('http'):
                urlsTab = getDirectM3U8Playlist(url)
                return urlsTab
            elif url.startswith('livee.m3u8') or url.startswith('live.m3u8'):
                url = 'https://hd-auth.skylinewebcams.com/' + url.replace('livee', 'live', 1)
                urlsTab = getDirectM3U8Playlist(url)
                return urlsTab
        else:
            url = self.cm.ph.getSearchGroups(data, '''videoId:\\s*['"]([^'"]+?)['"]''', 1, True)[0]
            if url:
                url = 'https://www.youtube.com/watch?v=%s' % url
                url = self.up.getVideoLink(url)
                urlsTab = getDirectM3U8Playlist(url)
                urlsTab.append({'name': "YouTuBe", 'url': url})
                return urlsTab
        return urlsTab

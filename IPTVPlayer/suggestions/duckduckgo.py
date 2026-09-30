# -*- coding: utf-8 -*-
#
from Plugins.Extensions.IPTVPlayer.p2p3.UrlLib import urllib_quote
try:
    import json
except Exception:
    import simplejson as json

from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.libs.pCommon import common
from Plugins.Extensions.IPTVPlayer.p2p3.manipulateStrings import ensure_str


class SuggestionsProvider:

    def __init__(self):
        self.cm = common()

    def getName(self):
        return _("DuckDuckGo Suggestions")

    def getSuggestions(self, text, locale):
        url = 'https://duckduckgo.com/ac/?q=%s' % urllib_quote(text)
        sts, data = self.cm.getPage(url)
        if sts:
            # [{"phrase": suggestion}, ...]
            return [ensure_str(item['phrase']) for item in json.loads(data) if item.get('phrase')]
        return None

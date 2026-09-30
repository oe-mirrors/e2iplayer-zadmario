# -*- coding: utf-8 -*-
#
try:
    import json
except Exception:
    import simplejson as json

from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.libs.pCommon import common
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printExc

from Plugins.Extensions.IPTVPlayer.p2p3.manipulateStrings import ensure_str
from Plugins.Extensions.IPTVPlayer.p2p3.UrlLib import urllib_quote
from Plugins.Extensions.IPTVPlayer.p2p3.pVer import isPY2


class SuggestionsProvider:

    def __init__(self):
        self.cm = common()

    def getName(self):
        return _("IMDb Suggestions")

    def getSuggestions(self, text, locale):
        # lower case, also the non-ASCII letters (Python 2: UTF-8 bytes)
        try:
            text = text.decode('utf-8').lower().encode('utf-8') if isPY2() else text.lower()
        except Exception:
            printExc()
            text = text.lower()
        text = text.strip()
        if len(text) > 2:
            # v3 API: plain JSON and any text (umlauts, other scripts). The
            # first path part is the query's first character ('x' works for
            # everything that is not a-z / 0-9).
            first = text[0:1] if text[0:1] in 'abcdefghijklmnopqrstuvwxyz0123456789' else 'x'
            url = 'https://v3.sg.media-imdb.com/suggestion/%s/%s.json' % (first, urllib_quote(text))
            sts, data = self.cm.getPage(url)
            if sts:
                # titles only (ids tt...), no people
                return [ensure_str(item['l']) for item in json.loads(data).get('d', []) if str(item.get('id', '')).startswith('tt') and item.get('l')]
        return None

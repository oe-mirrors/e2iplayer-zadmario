# -*- coding: utf-8 -*-
#
from Plugins.Extensions.IPTVPlayer.p2p3.UrlLib import urllib_quote
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.suggestions.opensearch import OpenSearchSuggestionsProvider


class SuggestionsProvider(OpenSearchSuggestionsProvider):

    def getName(self):
        return _("Bing Suggestions")

    def getUrl(self, text, locale):
        # mkt expects the locale of the keyboard layout as it is ("de-DE")
        return 'https://api.bing.com/osjson.aspx?query=%s&mkt=%s' % (urllib_quote(text), locale)

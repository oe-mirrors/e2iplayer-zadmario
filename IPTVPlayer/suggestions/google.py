# -*- coding: utf-8 -*-
#
from Plugins.Extensions.IPTVPlayer.p2p3.UrlLib import urllib_quote
from Plugins.Extensions.IPTVPlayer.components.iptvplayerinit import TranslateTXT as _
from Plugins.Extensions.IPTVPlayer.suggestions.opensearch import OpenSearchSuggestionsProvider


class SuggestionsProvider(OpenSearchSuggestionsProvider):

    def __init__(self, forYouyube=False):
        OpenSearchSuggestionsProvider.__init__(self)
        self.forYouyube = forYouyube

    def getName(self):
        return _("Youtube Suggestions") if self.forYouyube else _("Google Suggestions")

    def getUrl(self, text, locale):
        parts = locale.split('-')
        lang = parts[0]
        country = parts[-1].lower() if len(parts) > 1 else lang
        # ie/oe=utf-8: without them Google answers some languages (ru, ar,
        # el, tr, ...) in a legacy Windows code page, depending on the
        # User-Agent
        # client=firefox: "output=firefox" answers HTTP 400 since 2026-10 (box log 09.10.2026), same JSON reply
        return 'https://suggestqueries.google.com/complete/search?client=firefox&ie=utf-8&oe=utf-8&hl=%s&gl=%s%s&q=%s' % (lang, country, '&ds=yt' if self.forYouyube else '', urllib_quote(text))

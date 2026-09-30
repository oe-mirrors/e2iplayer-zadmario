# -*- coding: utf-8 -*-
#
try:
    import json
except Exception:
    import simplejson as json

from Plugins.Extensions.IPTVPlayer.libs.pCommon import common
from Plugins.Extensions.IPTVPlayer.p2p3.manipulateStrings import ensure_str


class OpenSearchSuggestionsProvider:
    # base of the providers whose API answers in the OpenSearch suggestions
    # format: [query, [suggestion, ...]] (Google, Bing)

    def __init__(self):
        self.cm = common()

    def getUrl(self, text, locale):
        # locale of the keyboard layout: 'de-DE', 'sr-Cyrl-CS'
        raise NotImplementedError

    def getSuggestions(self, text, locale):
        sts, data = self.cm.getPage(self.getUrl(text, locale))
        if sts:
            return [ensure_str(item) for item in json.loads(data)[1]]
        return None

# -*- coding: utf-8 -*-

###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc, byteify
###################################################
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import isPY2
###################################################
# FOREIGN import
###################################################
try:
    import json
except Exception:
    import simplejson as json
e2icjson = None
############################################


def loads(inputString, noneReplacement=None, baseTypesAsString=False, utf8=True):
    global e2icjson
    if e2icjson == None:
        if isPY2():
            try:
                from Plugins.Extensions.IPTVPlayer.libs.e2icjson import e2icjson
                e2icjson = e2icjson
            except Exception:
                e2icjson = False
        else:
            try:
                import e2icjson  #p3 should have it installed in site-packages through opkg
                e2icjson = e2icjson
            except Exception:
                e2icjson = False

    if e2icjson:
        printDBG(">> cjson ACELERATION noneReplacement[%s] baseTypesAsString[%s]" % (noneReplacement, baseTypesAsString))
        try:
            outString = e2icjson.decode(inputString, 2 if utf8 else 1)
        except Exception as e:
            # TEMPORARY: SHOULD BE DEEPLY INVESTIGATED why cjson sometimes fails but json not
            printDBG(">> cjson FAILED with EXCEPTION: %s" % str(e))
            printDBG("\t Problematic inputString = '%s'" % inputString)
            printDBG(">> Trying with regular json module")
            outString = json.loads(inputString)
    else:
        outString = json.loads(inputString)
    
    if utf8 or noneReplacement != None or baseTypesAsString != False:
        outString = byteify(outString, noneReplacement, baseTypesAsString)

    return outString


def dumps(inputString, *args, **kwargs):
    return json.dumps(inputString, *args, **kwargs)

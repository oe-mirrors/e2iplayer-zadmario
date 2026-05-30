# -*- coding: utf-8 -*-
#
#  IPTV downloader creator
#
#  $Id$
#
#
###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, printExc, IsExecutable
from Plugins.Extensions.IPTVPlayer.tools.iptvtypes import strwithmeta
from Plugins.Extensions.IPTVPlayer.libs.urlparser import urlparser
from Plugins.Extensions.IPTVPlayer.iptvdm.wgetdownloader import WgetDownloader
from Plugins.Extensions.IPTVPlayer.iptvdm.pwgetdownloader import PwgetDownloader
from Plugins.Extensions.IPTVPlayer.iptvdm.busyboxdownloader import BuxyboxWgetDownloader
from Plugins.Extensions.IPTVPlayer.iptvdm.m3u8downloader import M3U8Downloader
from Plugins.Extensions.IPTVPlayer.iptvdm.em3u8downloader import EM3U8Downloader
from Plugins.Extensions.IPTVPlayer.iptvdm.hlsdownloader import HLSDownloader
from Plugins.Extensions.IPTVPlayer.iptvdm.ehlsdownloader import EHLSDownloader
from Plugins.Extensions.IPTVPlayer.iptvdm.rtmpdownloader import RtmpDownloader
from Plugins.Extensions.IPTVPlayer.iptvdm.f4mdownloader import F4mDownloader
from Plugins.Extensions.IPTVPlayer.iptvdm.mergedownloader import MergeDownloader
from Plugins.Extensions.IPTVPlayer.iptvdm.ffmpegdownloader import FFMPEGDownloader
from Plugins.Extensions.IPTVPlayer.iptvdm.iptvdh import DMHelper
###################################################

###################################################
# FOREIGN import
###################################################
from Components.config import config
###################################################


def IsUrlDownloadable(url):
    if None != DownloaderCreator(url):
        return True
    else:
        return False

#29.05.26
def IsHlsLikeUrl(url):
    try:
        lowUrl = str(url).lower()
    except Exception:
        printExc()
        return False

    hlsMarkers = [
        '.m3u8',
        '/playlist/',
        'm3u8',
        'x-stream-inf'
    ]

    for marker in hlsMarkers:
        if marker in lowUrl:
            return True

    return False

###################################################
#29.05.26
###################################################
def DownloaderCreator(url):
    printDBG("DownloaderCreator url[%r]" % url)

    downloader = None
    downloaderParams = {}
    orgUrl = url

    try:
        url, downloaderParams = DMHelper.getDownloaderParamFromUrlWithMeta(url)
    except Exception:
        printExc()
        url = orgUrl
        downloaderParams = {}

    # Meta sicher holen
    urlMeta = {}
    try:
        urlMeta = getattr(orgUrl, 'meta', {})
        if not isinstance(urlMeta, dict):
            urlMeta = {}
    except Exception:
        printExc()
        urlMeta = {}

    # Fallback: einige Builds liefern alles schon in downloaderParams
    if not urlMeta and isinstance(downloaderParams, dict):
        urlMeta = downloaderParams

    proto = ''
    try:
        proto = urlMeta.get('iptv_proto', '')
    except Exception:
        printExc()
        proto = ''

    # Host-/Spezialfall für Downloader-Routing
    ffmpegCase = ''
    try:
        ffmpegCase = str(urlMeta.get('iptv_ffmpeg_case', ''))
    except Exception:
        printExc()
        ffmpegCase = ''

    # Fallback-Protokollerkennung aus URL
    if not proto:
        try:
            if isinstance(url, basestring):
                lowUrl = url.lower()
                if '.m3u8' in lowUrl:
                    proto = 'm3u8'
                elif lowUrl.startswith('merge://'):
                    proto = 'merge'
                elif lowUrl.startswith('mpd://') or '.mpd' in lowUrl:
                    proto = 'mpd'
                elif lowUrl.startswith('f4m://') or '.f4m' in lowUrl:
                    proto = 'f4m'
        except Exception:
            printExc()

    useFFmpeg = False
    try:
        useFFmpeg = bool(urlMeta.get('iptv_use_ffmpeg', False))
    except Exception:
        printExc()
        useFFmpeg = False

    printDBG("DownloaderCreator url[%s]" % url)
    printDBG("DownloaderCreator iptv_proto[%s] iptv_use_ffmpeg[%s] iptv_ffmpeg_case[%s]" % (proto, useFFmpeg, ffmpegCase))
    printDBG("DownloaderCreator downloaderParams[%s]" % downloaderParams)

    #################################################
    # WICHTIG:
    # Wenn iptv_use_ffmpeg=True gesetzt ist,
    # dann IMMER FFMPEGDownloader bevorzugen,
    # auch bei m3u8/HLS.
    #################################################
    if useFFmpeg:
        printDBG("DownloaderCreator: force FFMPEGDownloader by iptv_use_ffmpeg=True")
        try:
            downloader = FFMPEGDownloader()
        except Exception:
            printExc()
            downloader = None

        if downloader != None:
            return downloader

    #################################################
    # Host-/Spezialfälle, die gezielt über Meta
    # vom Parser markiert wurden
    #################################################
    if ffmpegCase == 'kinoger':
        printDBG("DownloaderCreator: force FFMPEGDownloader by iptv_ffmpeg_case=kinoger")
        try:
            downloader = FFMPEGDownloader()
        except Exception:
            printExc()
            downloader = None

        if downloader != None:
            return downloader

    if ffmpegCase == 'pornslash':
        printDBG("DownloaderCreator: force FFMPEGDownloader by iptv_ffmpeg_case=pornslash")
        try:
            downloader = FFMPEGDownloader()
        except Exception:
            printExc()
            downloader = None

        if downloader != None:
            return downloader

    #################################################
    # Standard-Zuordnung nach Protokoll
    #################################################
    try:
        if proto in ['m3u8', 'hls']:
            printDBG("DownloaderCreator: HLS/M3U8 -> HLSDownloader")
            downloader = HLSDownloader()

        elif proto in ['mpd', 'dash']:
            printDBG("DownloaderCreator: MPD/DASH -> FFMPEGDownloader")
            downloader = FFMPEGDownloader()

        elif proto in ['f4m']:
            printDBG("DownloaderCreator: F4M -> F4mDownloader")
            downloader = F4mDownloader()

        elif proto in ['merge']:
            printDBG("DownloaderCreator: MERGE -> MergeDownloader")
            downloader = MergeDownloader()

        elif proto in ['http', 'https', 'ftp', 'ftps']:
            if IsHlsLikeUrl(url):
                printDBG("DownloaderCreator: HTTP/HTTPS but HLS-like URL -> FFMPEGDownloader")
                downloader = FFMPEGDownloader()
            else:
                printDBG("DownloaderCreator: HTTP/HTTPS/FTP -> WgetDownloader")
                downloader = WgetDownloader()

        else:
            # Fallback nach URL-Endung
            lowUrl = ''
            try:
                lowUrl = url.lower()
            except Exception:
                printExc()
                lowUrl = ''

            if '.m3u8' in lowUrl:
                printDBG("DownloaderCreator: fallback .m3u8 -> HLSDownloader")
                downloader = HLSDownloader()
            elif '.f4m' in lowUrl:
                printDBG("DownloaderCreator: fallback .f4m -> F4mDownloader")
                downloader = F4mDownloader()
            elif '.mpd' in lowUrl:
                printDBG("DownloaderCreator: fallback .mpd -> FFMPEGDownloader")
                downloader = FFMPEGDownloader()
            elif IsHlsLikeUrl(lowUrl):
                printDBG("DownloaderCreator: fallback HLS-like URL -> FFMPEGDownloader")
                downloader = FFMPEGDownloader()
            else:
                printDBG("DownloaderCreator: fallback default -> WgetDownloader")
                downloader = WgetDownloader()

    except Exception:
        printExc()
        downloader = None

    return downloader

def UpdateDownloaderCreator(url):
    printDBG("UpdateDownloaderCreator url[%s]" % url)
    if url.startswith('https'):
        if IsExecutable(DMHelper.GET_WGET_PATH()):
            printDBG("UpdateDownloaderCreator WgetDownloader")
            return WgetDownloader()
        elif IsExecutable('python'):
            printDBG("UpdateDownloaderCreator PwgetDownloader")
            return PwgetDownloader()
    else:
        if IsExecutable('wget'):
            printDBG("UpdateDownloaderCreator BuxyboxWgetDownloader")
            return BuxyboxWgetDownloader()
        elif IsExecutable(DMHelper.GET_WGET_PATH()):
            printDBG("UpdateDownloaderCreator WgetDownloader")
            return WgetDownloader()
        elif IsExecutable('python'):
            printDBG("UpdateDownloaderCreator PwgetDownloader")
            return PwgetDownloader()
    printDBG("UpdateDownloaderCreator downloader not available")
    return PwgetDownloader()

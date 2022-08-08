#!/bin/sh
[ `grep -c 'osd.language=pl_PL' </etc/enigma2/settings` -gt 0 ] && isPL=1 || isPL=0

cd /tmp
[ -e /tmp/e2iplayer-master.zip ] && rm -f /tmp/e2iplayer-master.zip
[ -e /tmp/e2iplayer-master ] && rm -fr /tmp/e2iplayer-master
wget -q https://gitlab.com/zadmario/e2iplayer/-/archive/master/e2iplayer-master.tar.gz -O /tmp/e2iplayer-master.zip
if [ $? -gt 0 ] ;then
  wget -q "--no-check-certificate" https://gitlab.com/zadmario/e2iplayer/-/archive/master/e2iplayer-master.tar.gz -O /tmp/e2iplayer-master.zip
  if [ $? -gt 0 ] ;then
    [ $isPL -eq 1 ] && echo "błąd pobierania archiwum, koniec" || echo "error downloading archive, end"
    exit 1
  fi
else
	[ $isPL -eq 1 ] && echo "Archiwum pobrane" || echo "Archive downloaded"
fi
tar -xzf /tmp/e2iplayer-master.zip -C /tmp
if [ $? -gt 0 ] ;then
	[ $isPL -eq 1 ] && echo "błąd rozpakowania archiwum, koniec" || echo "error extracting archive, end"
	exit 1
else
	[ $isPL -eq 1 ] && echo "Archiwum rozpakowane" || echo "Archive extracted"
	rm -f /tmp/e2iplayer-master.zip
fi

pyVer=`python -c "import sys;print(sys.version_info.major)"`

if [ $pyVer -eq 2 ];then
	[ $isPL -eq 1 ] && echo "Wykryto system z python2" || echo "Found system using python2"
else
	[ $isPL -eq 1 ] && echo "Wykryto system z python3" || echo "Found system using python3"
fi

if [ -e /usr/lib/enigma2/python/Plugins/Extensions/IPTVPlayer ];then
	rm  -rf /usr/lib/enigma2/python/Plugins/Extensions/IPTVPlayer
	[ $isPL -eq 1 ] && echo "Skasowano starą wersję E2Iplayera" || echo "Removed old version of E2Iplayer"
fi
mv -f /tmp/e2iplayer-master/IPTVPlayer /usr/lib/enigma2/python/Plugins/Extensions/
if [ $? -gt 0 ] ;then
	[ $isPL -eq 1 ] && echo "błąd instalacji E2Iplayera, koniec" || echo "error installing E2Iplayer, end"
	exit 1
else
	[ $isPL -eq 1 ] && echo "E2Iplayer zainstalowany" || echo "E2Iplayer installed"
	rm -fr /tmp/e2iplayer-master
fi

if [ -e /etc/opkg/opkg.conf ];then
  [ $isPL -eq 1 ] && echo "Próbuję doinstalować brakujące pakiety z opkg" || echo "trying to install missing opkg packets"
  opkg update > /dev/null 2>&1
  opkg install python-html > /dev/null 2>&1
  opkg install python-json > /dev/null 2>&1
  [  $? -ne 0 ] && opkg install python-simplejson  > /dev/null 2>&1
  opkg install python-compression > /dev/null 2>&1
  opkg install openssl-bin > /dev/null 2>&1
  [ `opkg list-installed|grep -c duktape` -eq 0 ] && opkg install duktape > /dev/null 2>&1
  [ `opkg list-installed|grep -c python3-e2icjson` -eq 0 ] && opkg install python3-e2icjson > /dev/null 2>&1
  [ `opkg list-installed|grep -c python-e2icjson` -eq 0 ] && opkg install python-e2icjson > /dev/null 2>&1
  [ `opkg list-installed|grep -c cmdwrap` -eq 0 ] && opkg install cmdwrap > /dev/null 2>&1
  [ `opkg list-installed|grep -c exteplayer3` -eq 0 ] && opkg install exteplayer3 > /dev/null 2>&1
  [ `opkg list-installed|grep -c gstplayer` -eq 0 ] && opkg install gstplayer > /dev/null 2>&1
  
fi
[ $isPL -eq 1 ] && echo "KONIEC - przeładuj teraz E2" || echo "END - reload E2"
sync

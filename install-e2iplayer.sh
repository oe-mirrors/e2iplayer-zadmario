#!/bin/sh

cd /tmp
[ -e /tmp/e2iplayer-master.tar.gz ] && rm -f /tmp/e2iplayer-master.tar.gz
[ -e /tmp/e2iplayer-zadmario-master ] && rm -fr /tmp/e2iplayer-zadmario-master
wget -q https://github.com/oe-mirrors/e2iplayer-zadmario/archive/refs/heads/master.tar.gz -O /tmp/e2iplayer-master.tar.gz
if [ $? -gt 0 ] ; then
	wget -q "--no-check-certificate" https://github.com/oe-mirrors/e2iplayer-zadmario/archive/refs/heads/master.tar.gz -O /tmp/e2iplayer-master.tar.gz
	if [ $? -gt 0 ] ; then
		echo -e "\nError ! downloading archive failed, end."
		exit 1
	fi
else
	echo -e "\nArchive successfully downloaded.\n"
fi

tar -xzf /tmp/e2iplayer-master.tar.gz -C /tmp
if [ $? -gt 0 ] ; then
	echo "Error ! extracting archive failed, end."
	exit 1
else
	echo "Archive successfully extracted."
	rm -f /tmp/e2iplayer-master.tar.gz
fi

pyVer=`python -c "import sys;print(sys.version_info.major)"`
if [ $pyVer -eq 2 ];then
	echo -e "\nFound system using python2.\n"
else
	echo -e "\nFound system using python3.\n"
fi

if [ -e /usr/lib/enigma2/python/Plugins/Extensions/IPTVPlayer ];then
	rm  -rf /usr/lib/enigma2/python/Plugins/Extensions/IPTVPlayer
	echo "Old E2iPlayer version deleted."
fi
mv -f /tmp/e2iplayer-zadmario-master/IPTVPlayer /usr/lib/enigma2/python/Plugins/Extensions/
if [ $? -gt 0 ] ;then
	echo -e "\nError ! installing E2iPlayer, end."
	exit 1
else
	echo -e "\nE2iPlayer successfully installed ! ! ! \n"
	rm -rf /tmp/e2iplayer-zadmario-master
fi

if [ -e /etc/opkg/opkg.conf ];then
	echo "trying to install missing opkg packets ..."
	opkg update > /dev/null 2>&1
	opkg install python-html > /dev/null 2>&1
	opkg install python-json > /dev/null 2>&1
	[  $? -ne 0 ] && opkg install python-simplejson  > /dev/null 2>&1
	opkg install python-compression > /dev/null 2>&1
	opkg install openssl-bin > /dev/null 2>&1
	[ `opkg list-installed|grep -c duktape` -eq 0 ] && opkg install duktape > /dev/null 2>&1
	[ `opkg list-installed|grep -c python3-pycurl` -eq 0 ] && opkg install python3-pycurl > /dev/null 2>&1
	[ `opkg list-installed|grep -c python3-e2icjson` -eq 0 ] && opkg install python3-e2icjson > /dev/null 2>&1
	[ `opkg list-installed|grep -c python-e2icjson` -eq 0 ] && opkg install python-e2icjson > /dev/null 2>&1
	[ `opkg list-installed|grep -c cmdwrap` -eq 0 ] && opkg install cmdwrap > /dev/null 2>&1
	[ `opkg list-installed|grep -c exteplayer3` -eq 0 ] && opkg install exteplayer3 > /dev/null 2>&1
	[ `opkg list-installed|grep -c gstplayer` -eq 0 ] && opkg install gstplayer > /dev/null 2>&1
fi

echo -e "\nEND -> reload E2\n"
sync

#!/bin/sh

# Reading out the Python version, and depending on that, set the download address for the xxx stuff.
py_ver=$(python -c "import sys; print(sys.version_info.major)")
if [ $py_ver -eq 2 ] ; then
	echo -e "\nfound system using python2."
	dl_archive=http://www.blindspot.nhely.hu/hosts/iptv-host-xxx-master.tar.gz
else
	echo -e "\nfound system using python3."
	dl_archive=http://www.blindspot.nhely.hu/python3/iptv-host-xxx-master-python3.tar.gz
fi

# Delete any remains of previous installations.
rm -rf /tmp/e2iplayer-* /tmp/iptv-host-xxx* /tmp/xxx.tar.gz

# Download E2iPlayer package. 
e2iplayer_downl_file=https://github.com/oe-mirrors/e2iplayer-zadmario/archive/refs/heads/master.tar.gz
if ! wget -q $e2iplayer_downl_file -O /tmp/e2iplayer-master.tar.gz ; then
	if ! wget -q "--no-check-certificate" $e2iplayer_downl_file -O /tmp/e2iplayer-master.tar.gz ; then
		echo -e "\nError ! downloading archive failed, end."
		exit 1
	fi
fi
echo -e "\narchive successfully downloaded.\n"

# Extract the E2iPlayer package.
if ! tar -xzf /tmp/e2iplayer-master.tar.gz -C /tmp ; then
	echo "Error ! extracting archive failed, end."
	exit 1
else
	echo "archive successfully extracted."
	rm -f /tmp/e2iplayer-master.tar.gz
fi

# Delete any existing E2iPlayer.
if [ -e /usr/lib/enigma2/python/Plugins/Extensions/IPTVPlayer ] ; then
	rm  -rf /usr/lib/enigma2/python/Plugins/Extensions/IPTVPlayer
	echo -e "\nold E2iPlayer version deleted."
fi

# Move newly downloaded E2iPlayer to /usr/lib/enigma2/python/Plugins/Extensions.
if ! mv -f /tmp/e2iplayer-zadmario-master/IPTVPlayer /usr/lib/enigma2/python/Plugins/Extensions/ ; then
	echo -e "\nError ! installing E2iPlayer, end."
	exit 1
else
	echo -e "\nE2iPlayer successfully installed ! ! ! \n"
	rm -rf /tmp/e2iplayer-zadmario-master
fi

# Try to reinstall dependent packages from the feed, otherwise the missing packages will be installed when you start E2iPlayer for the first time.
if [ -e /etc/opkg/opkg.conf ] ; then
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

# xxx Install.
xxx_package=xxx.tar.gz
if ! wget -q "--no-check-certificate" $dl_archive -O /tmp/$xxx_package ; then
	echo -e "\nError ! downloading xxx archive failed, end."
	xxx_install=failed
else
	echo -e "\nxxx archive successfully downloaded.\n"
fi

# Extract the xxx.tar.gz archive (variable xxx_package).
if ! tar -xzf /tmp/$xxx_package -C /tmp 2>/dev/null ; then
	echo "Error ! extracting xxx archive failed, end."
	xxx_install=failed
else
	echo "xxx archive successfully extracted."
	rm -f /tmp/xxx.tar.gz
fi

# Set source for python2 or python3.
source_py3=iptv-host-xxx-master-python3
source_py2=iptv-host-xxx-master
if [ -d /tmp/$source_py2 ] ; then
	source=$source_py2
elif [ -d /tmp/$source_py3 ] ; then
	source=$source_py3
fi
echo -e "\ntemporary xxx directory = /tmp/$source\n" 

# Copy xxx files to the correct directory.
if ! cp -rf /tmp/$source/IPTVPlayer /usr/lib/enigma2/python/Plugins/Extensions/ ; then
	echo "Error ! xxx files could not be copied to the correct directory, end."
	xxx_install=failed
else
	echo "copying xxx files to the correct directory successfully completed."
	rm -rf /tmp/$source
fi

# xxx Install Check.
if [ "$xxx_install" = "failed" ] ; then
	echo -e "\n\nUnfortunately, xxx install has failed."
fi

# Endmessage.
echo -e "\n\n! ! ! END -> Enigma2 GUI restart needed ! ! !\n\n\n"
sync

# Enigma2 GUI restart, yes or no ?, it's your decision (if there are currently no timer recordings running the answer would be yes).
while true; do
	read -p "$(echo -e "\nWould you like to restart the Enigma2 GUI? y/n (Default = yes) ?")" -n 1 yn
	case $yn in
		[yY]* )	echo -e "\n\nEnigma2 GUI restart is executed ...\n"
				wget -q -O - http://127.0.0.1/web/powerstate?newstate=3
				echo -e "\n" && break ;;
		[nN]* ) echo -e "\n" && break ;;
			* ) if [ -z "$yn" ] ; then
					echo -e "\n\nEnigma2 GUI restart is executed ...\n"
					wget -q -O - http://127.0.0.1/web/powerstate?newstate=3
					echo -e "\n" && break
				fi
				echo -e "\n\nPlease answer with y for (yes) or n for (no).\n" ;;
	esac
done

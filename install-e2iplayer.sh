#!/bin/sh

#e2iplayer install script - modified by Pike_Bishop from oATV

## Variables ##
scriptversion=16.0.3_git-zadmario_fork_for_other_images
startdate="$(date +%a.%d.%b.%Y-%H:%M:%S)"
workdir=/home/root/_workdir
target_path=/usr/lib/enigma2/python/Plugins/Extensions
e2iplayer_downl_package=https://github.com/oe-mirrors/e2iplayer-zadmario/archive/refs/heads/master.tar.gz
logfile=$workdir/_e2iplayer_install.log

# If it does not exist create the Working Directory (this is where the Log file are stored).
mkdir -p $workdir

{
# script Name + script Version Output + E2iPlayer Installation Start Message.
echo -e "\nScript-Name/Version -> e2iplayer-install.sh\t  Version_$scriptversion\n"
echo -e "\nInstall/Update E2iPlayer ... -> $startdate\n\n"

# Delete any remains of previous installations.
rm -rf /tmp/e2iplayer-* /tmp/iptv-host-xxx* /tmp/xxx.tar.gz

# Download E2iPlayer package. 
if ! wget -q $e2iplayer_downl_package -O /tmp/e2iplayer-master.tar.gz ; then
	if ! wget -q "--no-check-certificate" $e2iplayer_downl_package -O /tmp/e2iplayer-master.tar.gz ; then
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
if [ -e $target_path/IPTVPlayer ] ; then
	rm  -rf $target_path/IPTVPlayer
	echo -e "\nold E2iPlayer version deleted."
fi

# Move newly downloaded E2iPlayer to /usr/lib/enigma2/python/Plugins/Extensions (target_path).
if ! mv -f /tmp/e2iplayer-zadmario-master/IPTVPlayer $target_path/ ; then
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
xxx_targetdir=$target_path/IPTVPlayer/hosts
# Reading out the python version, and depending on that, set the download address for the xxx stuff.
python_version=$(python -c "import sys; print(sys.version_info.major)")
if [ $python_version -eq 2 ] ; then
	echo -e "\nfound system using python2."
	xxx_file=http://www.krapulax2023.nhely.hu/Python2/hosts/hostXXX.py
	# For python2, rename the existing icon files to XXX*.png (i.e., to XXX in capital letters).
	icon_path=$target_path/IPTVPlayer/icons
	mv $icon_path/logos/xxxlogo.png $icon_path/logos/XXXlogo.png ; echo -e "\nrename xxxlogo.png = $?"
	mv $icon_path/PlayerSelector/xxx100.png $icon_path/PlayerSelector/XXX100.png ; echo "rename xxx100.png = $?"
	mv $icon_path/PlayerSelector/xxx120.png $icon_path/PlayerSelector/XXX120.png ; echo "rename xxx120.png = $?"
	mv $icon_path/PlayerSelector/xxx135.png $icon_path/PlayerSelector/XXX135.png ; echo -e "rename xxx135.png = $?\n"
elif [ $python_version -eq 3 ] ; then
	echo -e "\nfound system using python3."
	xxx_file=http://www.krapulax2023.nhely.hu/Python3/hostxxx.py
fi

echo -e "\nDownload xxx (+18 addon host) to;\n$xxx_targetdir ...\n"
if ! wget "--no-check-certificate" $xxx_file -P $xxx_targetdir ; then
	echo -e "\n... ERROR ...\nDownload xxx (+18 addon host) failed ! \nCheck your Internet connection\nand restart the Script.\n"
else
	echo -e "\nxxx (+18 addon host) successfully installed ! ! ! \n"
fi

# E2iPlayer Installation/Update success Message, and delete remains.
enddate="$(date +%a.%d.%b.%Y-%H:%M:%S)"
echo -e "\n\nE2iPlayer installed/updated successfully. -> $enddate\n"
rm -rf /tmp/e2iplayer-* /tmp/iptv-host-xxx* /tmp/xxx.tar.gz
echo -e "\n\n! ! ! END -> Enigma2 GUI restart needed, either immediately or later ! ! !\n\n"
sync

# Enigma2 GUI restart, yes or no ?, it's your decision (if there are currently no timer recordings running the answer would be yes).
while true; do
	read -p "$(echo -e "\nWould you like to restart the Enigma2 GUI? y/n (Default = yes) ?")" -n 1 yn < /dev/tty
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

} 2>&1 | tee $logfile

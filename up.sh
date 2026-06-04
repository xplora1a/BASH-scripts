#! /bin/bash
# update the systems and backup various settings
sname="$(cat /etc/hostname)"
echo "Updateing  ${sname}"
sudo apt update && sudo apt upgrade -y
if [ -x /usr/bin/flatpak ]; then
	echo "Flatpak updates"
	sudo flatpak update -y
fi
if [ -x /usr/bin/snap ]; then
	echo "Snap updates"
	sudo snap refresh
fi
echo "Check the version of Zoom available"
location=$(curl -L -i -s --max-redirs 0 https://zoom.us/client/latest/zoom_amd64.deb | grep "location:")
version=$(echo "$location" | sed -E 's#.*prod/([0-9.]+)/.*#\1#')
#get the version installed
installed=$(dpkg -s zoom | grep "Version:" | awk '{print $2}')
echo "Installed version: $installed Latest version: $version"
if [ "$installed" != "$version" ]; then
    echo "Zoom is not up to date. Getting latest version."
    curl -L -o "${HOME}"/Downloads/zoom_amd64-"${version}".deb https://zoom.us/client/latest/zoom_amd64.deb    
fi
if [ -x ~/Documents/settings/"${sname}"/ssh ]; then
	echo "Backing up ssh config"
	cp -auv ~/.ssh/* ~/Documents/settings/"${sname}"/ssh/
fi
if [ -x ~/Documents/settings/"${sname}"/netplan ]; then
	echo "Backing up network connection config"
	sudo cp -auv /etc/netplan/* ~/Documents/settings/"${sname}"/netplan/
	sudo chown stuart:stuart ~/Documents/settings/"${sname}"/netplan/*
fi


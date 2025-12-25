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
if [ -x ~/Documents/settings/"${sname}"/ssh ]; then
	echo "Backing up ssh config"
	cp -auv ~/.ssh/* ~/Documents/settings/"${sname}"/ssh/
fi
if [ -x ~/Documents/settings/"${sname}"/netplan ]; then
	echo "Backing up network connection config"
	sudo cp -auv /etc/netplan/* ~/Documents/settings/"${sname}"/netplan/
	sudo chown stuart:stuart ~/Documents/settings/"${sname}"/netplan/*
fi


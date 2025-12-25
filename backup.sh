#! /usr/bin/bash

if [ -z $(dig +short gnubee.lan ) ]
   then
	echo "Not on local LAN aborting!!"
   else
	echo "On local LAN starting backup"
	dirs=("Calibre" "Pictures" "Music" "Documents" "Dropbox" "projects")
	for dir in "${dirs[@]}"
       	do
	    echo "Starting backup of ${dir}"
	    rsync -av /home/stuart/"${dir}"/ gnubee.lan:/home/stuart/"${dir}"/
        done
fi


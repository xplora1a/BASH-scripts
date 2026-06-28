#! /bin/bash
# Get the version of Zoom available as that latest download
location=$(curl -L -i -s --max-redirs 0 https://zoom.us/client/latest/zoom_amd64.deb | grep "location:")
version=$(echo "$location" | sed -E 's#.*prod/([0-9.]+)/.*#\1#')
#get the version installed
installed=$(dpkg -s zoom | grep "Version:" | awk '{print $2}')
echo "Installed version: $installed"
echo "Latest version: $version"
if [ "$installed" != "$version" ]; then
    if [ -f "${HOME}"/Downloads/zoom_amd64-"${version}".deb ]; then
        echo "Zoom is not up to date. Latest version already downloaded."
    else
        echo "Zoom is not up to date. Getting latest version."
        curl -L -o "${HOME}"/Downloads/zoom_amd64-"${version}".deb https://zoom.us/client/latest/zoom_amd64.deb
    fi
fi
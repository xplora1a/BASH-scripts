#! /bin/bash
install=false
case "$1" in
    -i|--install)
        install=true
        ;;
    "")
        ;;
    *)
        echo "Usage: $0 [--install|-i]"
        exit 2
        ;;
esac

# Get the version of Zoom available as that latest download
location=$(curl -L -i -s --max-redirs 0 https://zoom.us/client/latest/zoom_amd64.deb | grep "location:")
version=$(echo "$location" | sed -E 's#.*prod/([0-9.]+)/.*#\1#')
package="${HOME}/Downloads/zoom_amd64-${version}.deb"
#get the version installed
installed=$(dpkg -s zoom | grep "Version:" | awk '{print $2}')
if [ -z "$installed" ]; then
    echo "Zoom is not installed."
    installed="none"
fi
echo "Installed version: $installed"
echo "Latest version: $version"
if [ "$installed" != "$version" ]; then
    if [ -f "$package" ]; then
        echo "Zoom is not up to date. Latest version already downloaded."
    else
        echo "Zoom is not up to date. Getting latest version."
        curl -L -o "$package" https://zoom.us/client/latest/zoom_amd64.deb
    fi
fi

if $install && [ "$installed" != "$version" ]; then
    echo "Installing Zoom ${version}."
    sudo apt install -y "$package"
fi

#! /bin/bash

# Rename video files in the current directory to a have the S<year>E<number> format
# if the file creation date is 2004 and this is the first one in that year 
# it will be renamed to S2004E01.<ext> and all the associated files would have the same format despice their creation date
yearstart=2024
yearend=2024

for file in *.mp4 *.mkv
do
    echo "Processing file ${file}"
    if test -f "${file}"
    then
        year=$(date -r "${file}" +%Y)
        if (( year < yearstart )); then
            yearstart=$year
        elif (( year > yearend )); then
            yearend=$year
        fi
        tag=$(echo "${file}" | grep -oP '\-\K[a-z0-9]{8}(?=\.mp4|\.mkv)')
        if [ -z "${tag}" ]; then
            echo "No tag found in file ${file}, skipping"
            continue
        fi
        echo "File ${file} year ${year} tag ${tag}"
        for thisfile in *${tag}*.mp4 *${tag}*.mkv
        do
            echo "Renaming file ${thisfile} to year ${year}"
            rename "s/[Ss][0-9]*[Ee]/S${year}E/" "${thisfile}"
        done
    fi
done

# now go from yearstart to yearend and set the episode numbers based on the order of creation date
for (( year=yearstart; year<=yearend; year++ ))
do
    echo "Processing year ${year}"
    count=1
    for file in $(find ./ -name "*S${year}E*\.mp4" -type f -printf "%T+\t%p\n" | sort | cut -f2)
    do
        echo "Processing file ${file} for year ${year} count ${count}"
        if test -f "${file}"
        then
            tag=$(echo "${file}" | grep -oP '\-\K[a-z0-9]{8}(?=\.mp4|\.mkv)')
            if [ -z "${tag}" ]; then
                echo "No tag found in file ${file}, skipping"
                continue
            fi
            echo "File ${file} year ${year} tag ${tag} count ${count}"
            for thisfile in *${tag}*
            do
                echo "Sequencing file ${thisfile} year ${year} count ${count}"
                rename "s/[Ss][0-9]*[Ee][0-9]*/S${year}E$(printf '%02d' ${count})/" "${thisfile}"
            done
            ((count++))
        fi
    done
done

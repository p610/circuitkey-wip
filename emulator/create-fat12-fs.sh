#!/bin/bash

SIZE_IN_MB=1

if [ -f fat12.checksum ]; then
    checksum=$(cat fat12.checksum)
    if [ "$checksum" == "$(tar cf - ./fat12 | sha256sum)" ]; then
        echo "fat12.img already exists and is up to date"
        exit 0
    fi
fi

[ -f fat12.img ] && rm fat12.img


echo "= Creating fat12.img with size $SIZE_IN_MB MB" 

dd if=/dev/zero of=fat12.img bs=1M count=$SIZE_IN_MB \
    && mkfs.vfat -F12 -S512 fat12.img

echo "= Copying files from ./fat12 to fat12.img" 

python3 << EOF
from fs.copy import copy_fs
copy_fs('./fat12', "fat://fat12.img")
EOF

echo "= fat12.img created"

echo "= Listing files in fat12.img"
python3 << EOF
from fs import open_fs
fs = open_fs("fat://./fat12.img")
for file in fs.walk.files():
    info = fs.getinfo(file)
    print(f"  {info.size} bytes - {file}")
EOF

echo "= Creating checksum for fat12.img"
tar cf - ./fat12 | sha256sum > fat12.checksum


#!/bin/bash

echo '== Building circuitpython image. It might take a while.'
docker build -t circuitpython .

container_id=$(docker run -td circuitpython)
echo '== Container ID: ' ${container_id}

function cleanup() {
    echo "== Cleaning up... Removing container ${container_id}"
    docker rm ${container_id} -f 2>/dev/null
}
trap cleanup EXIT INT

echo '== Copying firmware to host.'

docker cp ${container_id}:/circuitpython/ports/raspberrypi/build-waveshare_rp2040_zero/firmware.uf2 .

cleanup

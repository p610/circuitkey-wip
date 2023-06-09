FROM debian:11-slim

ARG VERSION=8.0.3

RUN apt-get update \
    && apt-get install -y git build-essential wget

RUN git clone https://github.com/adafruit/circuitpython.git \
    && cd /circuitpython \
    && git checkout "$VERSION" \
    && make fetch-submodules

RUN wget -qO- \
    https://developer.arm.com/-/media/Files/downloads/gnu-rm/10.3-2021.10/gcc-arm-none-eabi-10.3-2021.10-x86_64-linux.tar.bz2 | tar -xvj -C /opt/

ENV PATH="/opt/gcc-arm-none-eabi-10.3-2021.10/bin:${PATH}"

RUN apt-get update && apt-get install -y \
    pkg-config \
    libffi-dev \
    wget \
    gettext \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN cd circuitpython \
    && pip3 install -r requirements-dev.txt

RUN cd circuitpython \
    && make -C mpy-cross 

ADD ./lib /circuitpython/usercmodule

# not tested with other boards
ENV BOARD="waveshare_rp2040_zero"

ENV PLATFORM="raspberrypi"

ENV BOARD_CFG="/circuitpython/ports/${PLATFORM}/boards/${BOARD}/mpconfigboard.mk"

RUN echo "CIRCUITPY_SSL_MBEDTLS = 1" >> /circuitpython/ports/${PLATFORM}/boards/${BOARD}/mpconfigboard.mk 

RUN cd /circuitpython/ports/${PLATFORM} \
    && make BOARD=${BOARD} USER_C_MODULES=/circuitpython/usercmodule
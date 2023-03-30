EXAMPLE_MOD_DIR := $(USERMOD_DIR)

MBEDTLS_DIR = /circuitpython/lib/mbedtls

CFLAGS_USERMOD += -I$(EXAMPLE_MOD_DIR) -I$(MBEDTLS_DIR)/include
CRYPTO_MOD_DIR := $(USERMOD_DIR)

SRC_MBEDTLS := $(addprefix lib/mbedtls/library/, \
        ecdh.c \
        ecdsa.c \
		ecp.c \
		ecp_curves.c \
		aes.c \
		sha256.c \
		sha512.c \
		entropy.c \
		platform.c \
		platform_util.c \
		error.c \
		bignum.c \
		ctr_drbg.c \
)

SRC_USERMOD += $(SRC_MBEDTLS) 
SRC_USERMOD += /circuitpython/ports/raspberrypi/mbedtls/mbedtls_port.c 
SRC_USERMOD += $(EXAMPLE_MOD_DIR)/crypto.c

CFLAGS += \
	  -isystem $(TOP)/lib/mbedtls/include \
	  -DMBEDTLS_CONFIG_FILE='"mbedtls/mbedtls_config.h"' 

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "py/obj.h"
#include "py/builtin.h"
#include "py/runtime.h"
#include "py/objtuple.h"

#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

void sharedsecret_cleanup(mbedtls_ecdh_context *ctx, mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy, const char *reason);

STATIC mp_obj_t crypto_shared_secret(mp_obj_t a_x, mp_obj_t a_y, mp_obj_t a_private_key)
{
    // check arguments
    {
        mp_obj_t args[] = {a_x, a_y, a_private_key};

        for (int i = 0; i < 3; i++)
        {
            if (!mp_obj_is_type(args[i], &mp_type_bytes))
            {
                mp_raise_ValueError(MP_ERROR_TEXT("Argument is not bytes"));
            }

            size_t len = mp_obj_get_int(mp_obj_len(args[i]));
            if (len != 32)
            {
                mp_raise_ValueError(MP_ERROR_TEXT("Argument is not 32 bytes long"));
            }
        }
    }

    // convert arguments
    size_t len = 32;
    unsigned char *x = (unsigned char *)mp_obj_str_get_data(a_x, &len);
    unsigned char *y = (unsigned char *)mp_obj_str_get_data(a_y, &len);
    unsigned char *private_key = (unsigned char *)mp_obj_str_get_data(a_private_key, &len);

    // contexts
    mbedtls_ecdh_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecdh_init(&ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "mbedtls_ecdh_shared_key";

    // seed entropy source
    if ((mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
    {
        sharedsecret_cleanup(&ctx, &ctr_drbg, &entropy, "Cannot seed entropy source");
    }

    // load group
    if ((mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1)) != 0)
    {
        sharedsecret_cleanup(&ctx, &ctr_drbg, &entropy, "Cannot load group");
    }

    // load private key
    if ((mbedtls_mpi_read_binary(&ctx.d, private_key, 32)) != 0)
    {
        sharedsecret_cleanup(&ctx, &ctr_drbg, &entropy, "Cannot load private key");
    }

    // load x and y coordinates of public key
    if ((mbedtls_mpi_read_binary(&ctx.Q.X, x, 32)) != 0)
    {
        sharedsecret_cleanup(&ctx, &ctr_drbg, &entropy, "Cannot load x coordinate");
    }

    if ((mbedtls_mpi_read_binary(&ctx.Q.Y, y, 32)) != 0)
    {
        sharedsecret_cleanup(&ctx, &ctr_drbg, &entropy, "Cannot load y coordinate");
    }

    // generate shared secret
    unsigned char shared_secret[32];

    if ((mbedtls_ecdh_compute_shared(&ctx.grp, &ctx.z, &ctx.Q, &ctx.d, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        sharedsecret_cleanup(&ctx, &ctr_drbg, &entropy, "Cannot generate shared secret");
    }

    // write shared secret to buffer and return it
    if ((mbedtls_mpi_write_binary(&ctx.z, shared_secret, 32)) != 0)
    {
        sharedsecret_cleanup(&ctx, &ctr_drbg, &entropy, "Cannot write shared secret");
    }

    sharedsecret_cleanup(&ctx, &ctr_drbg, &entropy, NULL);

    mp_obj_t shared_secret_bytes = mp_obj_new_bytes(shared_secret, 32);

    return shared_secret_bytes;
}

void sharedsecret_cleanup(mbedtls_ecdh_context *ctx, mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy, const char *reason)
{
    if (ctx != NULL)
    {
        mbedtls_ecdh_free(ctx);
    }
    if (ctr_drbg != NULL)
    {
        mbedtls_ctr_drbg_free(ctr_drbg);
    }
    if (entropy != NULL)
    {
        mbedtls_entropy_free(entropy);
    }
    if (reason != NULL)
    {
        mp_raise_ValueError(MP_ERROR_TEXT(reason));
    }
}

void ecdsakeys_cleanup(mbedtls_ecdsa_context *ctx, mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy, mbedtls_ecp_point *point, const char *reason);

STATIC mp_obj_t crypto_gen_keys(void)
{
    // contexts
    mbedtls_ecdsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_point point;

    const char *pers = "mbedtls_ecdsa_genkey";
    unsigned char private_key[32];
    unsigned char public_key[65];

    // init
    mbedtls_ecdsa_init(&ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecp_point_init(&point);
    mbedtls_entropy_init(&entropy);

    if ((mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) != 0))
    {
        ecdsakeys_cleanup(&ctx, &ctr_drbg, &entropy, &point, "Cannot seed entropy source");
    }

    // Generate ECDSA key pair
    if ((mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        ecdsakeys_cleanup(&ctx, &ctr_drbg, &entropy, &point, "Cannot generate ECDSA key pair");
    }

    // Extract public key
    if ((mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, NULL, public_key, 65)) != 0)
    {
        ecdsakeys_cleanup(&ctx, &ctr_drbg, &entropy, &point, "Cannot extract public key");
    }

    mp_obj_t public_key_xy[] = {
        // 1:33 bytes in public_key are X coordinate
        mp_obj_new_bytes(public_key + 1, 32),
        // 33:65 bytes in public_key are Y coordinate
        mp_obj_new_bytes(public_key + 33, 32),
    };

    // Extract private key
    if ((mbedtls_mpi_write_binary(&ctx.d, private_key, 32)) != 0)
    {
        ecdsakeys_cleanup(&ctx, &ctr_drbg, &entropy, &point, "Cannot extract private key");
    }

    mp_obj_t private_key_bytes = mp_obj_new_bytes(private_key, 32);

    mp_obj_t tuple[] = {mp_obj_new_tuple(2, public_key_xy), private_key_bytes};

    ecdsakeys_cleanup(&ctx, &ctr_drbg, &entropy, &point, NULL);

    return mp_obj_new_tuple(2, tuple);
}

void ecdsakeys_cleanup(mbedtls_ecdsa_context *ctx, mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy, mbedtls_ecp_point *point, const char *reason)
{
    if (ctx != NULL)
    {
        mbedtls_ecdsa_free(ctx);
    }
    if (ctr_drbg != NULL)
    {
        mbedtls_ctr_drbg_free(ctr_drbg);
    }
    if (entropy != NULL)
    {
        mbedtls_entropy_free(entropy);
    }
    if (point != NULL)
    {
        mbedtls_ecp_point_free(point);
    }
    if (reason != NULL)
    {
        mp_raise_ValueError(MP_ERROR_TEXT(reason));
    }
}

STATIC MP_DEFINE_CONST_FUN_OBJ_0(crypto_gen_keys_obj, crypto_gen_keys);
STATIC MP_DEFINE_CONST_FUN_OBJ_3(crypto_shared_secret_obj, crypto_shared_secret);

STATIC const mp_rom_map_elem_t crypto_module_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_crypto)},
    {MP_ROM_QSTR(MP_QSTR_gen_keys), MP_ROM_PTR(&crypto_gen_keys_obj)},
    {MP_ROM_QSTR(MP_QSTR_shared_secret), MP_ROM_PTR(&crypto_shared_secret_obj)},
};

STATIC MP_DEFINE_CONST_DICT(crypto_module_globals, crypto_module_globals_table);

const mp_obj_module_t crypto_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&crypto_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR_crypto, crypto_module, 1);

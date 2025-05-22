#include "diffie_hellman.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <fcntl.h>
#include <unistd.h>

void dh_init(DH_Context *ctx) {
    mpz_init(ctx->p);
    mpz_init(ctx->g);
    mpz_init(ctx->priv);
    mpz_init(ctx->pub);
}

void dh_free(DH_Context *ctx) {
    mpz_clear(ctx->p);
    mpz_clear(ctx->g);
    mpz_clear(ctx->priv);
    mpz_clear(ctx->pub);
}

int dh_generate_parameters(DH_Context *ctx, unsigned int bits) {
    gmp_randstate_t st;
    gmp_randinit_default(st);
    gmp_randseed_ui(st, (unsigned long) time(NULL));

    // generate safe prime p = 2q+1
    mpz_t q;
    mpz_init(q);
    // if (!mpz_urandomb(q, st, bits - 1)) { mpz_clear(q); return 0; }
    mpz_urandomb(q, st, bits - 1);
    if (mpz_cmp_ui(q, 0) == 0) { // 檢查 q 是否為 0
        mpz_clear(q);
        return 0;
    }
    mpz_nextprime(q, q);
    mpz_mul_ui(ctx->p, q, 2);
    mpz_add_ui(ctx->p, ctx->p, 1);
    mpz_nextprime(ctx->p, ctx->p);

    // set generator g = 2
    mpz_set_ui(ctx->g, 2);

    mpz_clear(q);
    gmp_randclear(st);
    return 1;
}

static unsigned long get_random_seed() {
    unsigned long seed;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, &seed, sizeof(seed)) == sizeof(seed)) {
            close(fd);
            return seed;
        }
        close(fd);
    }
    // fallback
    return (unsigned long)time(NULL) ^ (unsigned long)getpid();
}

int dh_generate_keypair(DH_Context *ctx) {
    gmp_randstate_t st;
    gmp_randinit_default(st);
    // gmp_randseed_ui(st, (unsigned long) time(NULL));
    gmp_randseed_ui(st, get_random_seed());

    // priv ∈ [1, p-2]
    mpz_sub_ui(ctx->priv, ctx->p, 2);
    mpz_urandomm(ctx->priv, st, ctx->priv);
    mpz_add_ui(ctx->priv, ctx->priv, 1);

    // pub = g^priv mod p
    mpz_powm(ctx->pub, ctx->g, ctx->priv, ctx->p);

    gmp_randclear(st);
    return 1;
}

int dh_export_public(const DH_Context *ctx, uint8_t **out, size_t *out_len) {
    *out_len = (mpz_sizeinbase(ctx->pub, 2) + 7) / 8;
    *out = malloc(*out_len);
    if (!*out) return 0;
    mpz_export(*out, NULL, 1, 1, 1, 0, ctx->pub);
    return 1;
}

int dh_compute_shared(DH_Context *ctx,
                      const uint8_t *peer, size_t peer_len,
                      uint8_t **secret, size_t *secret_len) {
    mpz_t peer_pub;
    mpz_init(peer_pub);
    mpz_import(peer_pub, peer_len, 1, 1, 1, 0, peer);

    mpz_t z;
    mpz_init(z);
    // shared z = peer_pub^priv mod p
    mpz_powm(z, peer_pub, ctx->priv, ctx->p);

    *secret_len = (mpz_sizeinbase(z,2) + 7) / 8;
    *secret = malloc(*secret_len);
    if (!*secret) { mpz_clear(peer_pub); mpz_clear(z); return 0; }
    mpz_export(*secret, NULL, 1, 1, 1, 0, z);

    mpz_clear(peer_pub);
    mpz_clear(z);
    return 1;
}

int dh_hmac_sign(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out, unsigned int *out_len)
{
    unsigned char *result = HMAC(
        EVP_sha256(), key, (int)key_len,
        data, data_len,
        out, out_len);
    return result != NULL;
}

int dh_hmac_verify(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   const uint8_t *mac, unsigned int mac_len)
{
    uint8_t expected[EVP_MAX_MD_SIZE];
    unsigned int expected_len = 0;
    if (!dh_hmac_sign(key, key_len, data, data_len, expected, &expected_len))
        return 0;
    if (expected_len != mac_len) return 0;
    return CRYPTO_memcmp(expected, mac, mac_len) == 0;
}

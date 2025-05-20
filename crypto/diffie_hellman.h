#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <stddef.h>
#include <stdint.h>
#include <gmp.h>

/**
 * @brief Ephemeral Diffie–Hellman context
 * 
 * p, g        — DH parameters
 * priv, pub   — local private and public values
 */
typedef struct {
    mpz_t p;
    mpz_t g;
    mpz_t priv;
    mpz_t pub;
} DH_Context;

/**
 * @brief Initialize a DH_Context (must call dh_free when done)
 */
void dh_init(DH_Context *ctx);

/**
 * @brief Free all mpz_t fields in ctx
 */
void dh_free(DH_Context *ctx);

/**
 * @brief Generate a new safe-prime group of given bit‐length
 * 
 * @param bits  number of bits for p (e.g. 2048)
 * @return      1 on success, 0 on failure
 */
int dh_generate_parameters(DH_Context *ctx, unsigned int bits);

/**
 * @brief Generate a fresh ephemeral keypair (priv/pub ← g^x mod p)
 * 
 * @return 1 on success, 0 on failure
 */
int dh_generate_keypair(DH_Context *ctx);

/**
 * @brief Export the public value ctx->pub into a big‐endian byte buffer
 * 
 * @param ctx
 * @param out       pointer to allocated buffer (caller must free)
 * @param out_len   receives length in bytes
 * @return          1 on success
 */
int dh_export_public(const DH_Context *ctx, uint8_t **out, size_t *out_len);

/**
 * @brief Compute the shared secret Z = peer_pub^priv mod p
 * 
 * @param ctx
 * @param peer     big‐endian peer public buffer
 * @param peer_len length of peer buffer
 * @param secret   pointer to allocated buffer (caller must free)
 * @param secret_len receives length in bytes
 * @return         1 on success
 */
int dh_compute_shared(DH_Context *ctx,
                      const uint8_t *peer, size_t peer_len,
                      uint8_t **secret, size_t *secret_len);


/*
 * HMAC‐SHA256 for message authentication over the shared secret or any data
 * You must link with -lcrypto
 */
#include <openssl/evp.h>
#include <openssl/hmac.h>

/**
 * @brief Compute HMAC-SHA256 over data using key
 * 
 * @param key       key bytes
 * @param key_len   key length
 * @param data      message bytes
 * @param data_len  message length
 * @param out       buffer of at least EVP_MAX_MD_SIZE bytes
 * @param out_len   receives actual MAC length
 * @return          1 on success
 */
int dh_hmac_sign(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out, unsigned int *out_len);

/**
 * @brief Verify HMAC-SHA256 over data using key
 * 
 * @return 1 if valid, 0 if invalid or error
 */
int dh_hmac_verify(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   const uint8_t *mac, unsigned int mac_len);

#endif // DIFFIE_HELLMAN_H

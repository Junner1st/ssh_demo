#ifndef RSA_H
#define RSA_H

#include <gmp.h>
#include <stddef.h>

// RSA 公鑰
typedef struct {
    mpz_t n; // modulus
    mpz_t e; // public exponent
} RSA_PublicKey;

// RSA 私鑰
typedef struct {
    mpz_t n; // modulus
    mpz_t d; // private exponent
} RSA_PrivateKey;

// 初始化與清理
void rsa_init_public_key(RSA_PublicKey *pub);
void rsa_clear_public_key(RSA_PublicKey *pub);

void rsa_init_private_key(RSA_PrivateKey *priv);
void rsa_clear_private_key(RSA_PrivateKey *priv);

// RSA 鑰匙對產生 (指定位元長度，如 2048)
void rsa_generate_key_pair(RSA_PublicKey *pub, RSA_PrivateKey *priv, unsigned int bits);

// 加密與解密 (明文、密文都以 mpz_t 表示)
void rsa_encrypt(mpz_t ciphertext, const mpz_t plaintext, const RSA_PublicKey *pub);
void rsa_decrypt(mpz_t plaintext, const mpz_t ciphertext, const RSA_PrivateKey *priv);

// 載入/儲存 鍵值（可選：你可以擴充這些接口）
int rsa_save_public_key(const char *filename, const RSA_PublicKey *pub);
int rsa_load_public_key(const char *filename, RSA_PublicKey *pub);

int rsa_save_private_key(const char *filename, const RSA_PrivateKey *priv);
int rsa_load_private_key(const char *filename, RSA_PrivateKey *priv);

int rsa_export_public_key_pem(const char *filename, const RSA_PublicKey *pub);
int rsa_export_private_key_pem(const char *filename, const RSA_PrivateKey *priv);
int rsa_import_public_key_pem(const char *filename, RSA_PublicKey *pub);
int rsa_import_private_key_pem(const char *filename, RSA_PrivateKey *priv);


#endif // RSA_H

#include "rsa.h"
#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>


// --- 初始化與清理 ---

void rsa_init_public_key(RSA_PublicKey *pub) {
    mpz_init(pub->n);
    mpz_init(pub->e);
}

void rsa_clear_public_key(RSA_PublicKey *pub) {
    mpz_clear(pub->n);
    mpz_clear(pub->e);
}

void rsa_init_private_key(RSA_PrivateKey *priv) {
    mpz_init(priv->n);
    mpz_init(priv->d);
}

void rsa_clear_private_key(RSA_PrivateKey *priv) {
    mpz_clear(priv->n);
    mpz_clear(priv->d);
}

// --- 產生鑰匙對 ---

void rsa_generate_key_pair(RSA_PublicKey *pub, RSA_PrivateKey *priv, unsigned int bits) {
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, (unsigned long) time(NULL));

    mpz_t p, q, phi, e, d, gcd;
    mpz_inits(p, q, phi, e, d, gcd, NULL);

    // 產生兩個不同的質數 p 和 q
    do {
        mpz_urandomb(p, state, bits / 2);
        mpz_nextprime(p, p);

        mpz_urandomb(q, state, bits / 2);
        mpz_nextprime(q, q);
    } while (mpz_cmp(p, q) == 0);

    // n = p * q
    mpz_mul(pub->n, p, q);
    mpz_set(priv->n, pub->n);

    // phi = (p - 1)(q - 1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, p, q);

    // 選擇 e（65537 是常見選擇）
    mpz_set_ui(e, 65537);

    // 確保 gcd(e, phi) == 1
    mpz_gcd(gcd, e, phi);
    while (mpz_cmp_ui(gcd, 1) != 0) {
        mpz_add_ui(e, e, 2);
        mpz_gcd(gcd, e, phi);
    }

    // 計算 d = e⁻¹ mod phi
    mpz_invert(d, e, phi);

    // 設定 public / private key
    mpz_set(pub->e, e);
    mpz_set(priv->d, d);

    // 清理
    mpz_clears(p, q, phi, e, d, gcd, NULL);
    gmp_randclear(state);
}

// --- 加密：ciphertext = plaintext^e mod n ---

void rsa_encrypt(mpz_t ciphertext, const mpz_t plaintext, const RSA_PublicKey *pub) {
    mpz_powm(ciphertext, plaintext, pub->e, pub->n);
}

// --- 解密：plaintext = ciphertext^d mod n ---

void rsa_decrypt(mpz_t plaintext, const mpz_t ciphertext, const RSA_PrivateKey *priv) {
    mpz_powm(plaintext, ciphertext, priv->d, priv->n);
}

// --- 公鑰儲存與載入 ---

int rsa_save_public_key(const char *filename, const RSA_PublicKey *pub) {
    FILE *f = fopen(filename, "w");
    if (!f) return 0;
    mpz_out_str(f, 16, pub->n); fprintf(f, "\n");
    mpz_out_str(f, 16, pub->e); fprintf(f, "\n");
    fclose(f);
    return 1;
}

int rsa_load_public_key(const char *filename, RSA_PublicKey *pub) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;
    // mpz_inp_str(pub->n, f, 16);
    rsa_import_public_key_pem(filename, pub);
    if (mpz_cmp_ui(pub->n, 0) == 0) {
        fprintf(stderr, "Error: Invalid public key (n is zero)\n");
        fclose(f);
        return 0; // 鍵值無效
    }
    // mpz_inp_str(pub->e, f, 16);
    if (mpz_cmp_ui(pub->e, 0) == 0) {
        fprintf(stderr, "Error: Invalid public key (e is zero)\n");
        fclose(f);
        return 0; // 鍵值無效
    }
    fclose(f);
    return 1;
}

// --- 私鑰儲存與載入 ---

int rsa_save_private_key(const char *filename, const RSA_PrivateKey *priv) {
    FILE *f = fopen(filename, "w");
    if (!f) return 0;
    mpz_out_str(f, 16, priv->n); fprintf(f, "\n");
    mpz_out_str(f, 16, priv->d); fprintf(f, "\n");
    fclose(f);
    return 1;
}

int rsa_load_private_key(const char *filename, RSA_PrivateKey *priv) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;
    rsa_import_private_key_pem(filename, priv);
    // mpz_inp_str(priv->n, f, 16);
    if (mpz_cmp_ui(priv->n, 0) == 0) {
        fprintf(stderr, "Error: Invalid private key (n is zero)\n");
        fclose(f);
        return 0; // 鍵值無效
    }
    // mpz_inp_str(priv->d, f, 16);
    if (mpz_cmp_ui(priv->d, 0) == 0) {
        fprintf(stderr, "Error: Invalid private key (d is zero)\n");
        fclose(f);
        return 0; // 鍵值無效
    }
    fclose(f);
    return 1;
}

static const char *b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_encode(const unsigned char *in, size_t len, char *out) {
    size_t i=0,j=0;
    while (i<len) {
        uint32_t octet_a = i<len ? in[i++] : 0;
        uint32_t octet_b = i<len ? in[i++] : 0;
        uint32_t octet_c = i<len ? in[i++] : 0;
        uint32_t triple = (octet_a<<16)|(octet_b<<8)|octet_c;
        out[j++] = b64_chars[(triple>>18)&0x3F];
        out[j++] = b64_chars[(triple>>12)&0x3F];
        out[j++] = (i>len+1)? '=' : b64_chars[(triple>>6)&0x3F];
        out[j++] = (i>len)?   '=' : b64_chars[triple&0x3F];
    }
    out[j]='\0';
}
static int b64_val(char c) {
    const char *p = strchr(b64_chars, c);
    return p ? (int)(p - b64_chars) : -1;
}
static unsigned char *base64_decode(const char *in, size_t *out_len) {
    size_t len = strlen(in), i=0,j=0;
    unsigned char *buf = malloc(len*3/4+1);
    while (i<len) {
        int v1=b64_val(in[i++]), v2=b64_val(in[i++]);
        int v3 = in[i]!='=' ? b64_val(in[i]) : 0; i++;
        int v4 = in[i]!='=' ? b64_val(in[i]) : 0; i++;
        uint32_t triple = (v1<<18)|(v2<<12)|(v3<<6)|v4;
        buf[j++] = (triple>>16)&0xFF;
        if (in[i-2] != '=') buf[j++] = (triple>>8)&0xFF;
        if (in[i-1] != '=') buf[j++] = triple&0xFF;
    }
    *out_len = j;
    return buf;
}

// --- PEM Export Public Key ---
int rsa_export_public_key_pem(const char *filename, const RSA_PublicKey *pub) {
    size_t n_bytes = (mpz_sizeinbase(pub->n,2)+7)/8;
    size_t e_bytes = (mpz_sizeinbase(pub->e,2)+7)/8;
    unsigned char *buf = malloc(4 + n_bytes + e_bytes);
    uint16_t nb = n_bytes, eb = e_bytes;
    memcpy(buf, &nb, 2);
    memcpy(buf+2, &eb, 2);
    mpz_export(buf+4, NULL, 1, 1, 1, 0, pub->n);
    mpz_export(buf+4+nb, NULL, 1, 1, 1, 0, pub->e);

    char *b64 = malloc((4+nb+eb)*2);
    base64_encode(buf, 4+nb+eb, b64);
    free(buf);

    FILE *f = fopen(filename,"w");
    if(!f) { free(b64); return 0; }
    fprintf(f,"-----BEGIN RSA PUBLIC KEY-----\n");
    for(size_t i=0; b64[i]; i+=64)
        fprintf(f,"%.64s\n",b64+i);
    fprintf(f,"-----END RSA PUBLIC KEY-----\n");
    fclose(f);
    free(b64);
    return 1;
}

// --- PEM Export Private Key ---
int rsa_export_private_key_pem(const char *filename, const RSA_PrivateKey *priv) {
    size_t n_bytes = (mpz_sizeinbase(priv->n,2)+7)/8;
    size_t d_bytes = (mpz_sizeinbase(priv->d,2)+7)/8;
    unsigned char *buf = malloc(4 + n_bytes + d_bytes);
    uint16_t nb = n_bytes, db = d_bytes;
    memcpy(buf, &nb, 2);
    memcpy(buf+2, &db, 2);
    mpz_export(buf+4, NULL, 1, 1, 1, 0, priv->n);
    mpz_export(buf+4+nb, NULL, 1, 1, 1, 0, priv->d);

    char *b64 = malloc((4+nb+db)*2);
    base64_encode(buf, 4+nb+db, b64);
    free(buf);

    FILE *f = fopen(filename,"w");
    if(!f) { free(b64); return 0; }
    fprintf(f,"-----BEGIN RSA PRIVATE KEY-----\n");
    for(size_t i=0; b64[i]; i+=64)
        fprintf(f,"%.64s\n",b64+i);
    fprintf(f,"-----END RSA PRIVATE KEY-----\n");
    fclose(f);
    free(b64);
    return 1;
}

// --- PEM Import Public Key ---
int rsa_import_public_key_pem(const char *filename, RSA_PublicKey *pub) {
    FILE *f = fopen(filename,"r");
    if(!f) return 0;
    char line[256], *b64 = NULL;
    size_t cap=0, len=0;
    while(fgets(line, sizeof(line), f)) {
        if(strstr(line,"-----")) continue;
        size_t l = strlen(line);
        while(l>0 && (line[l-1]=='\n'||line[l-1]=='\r')) line[--l]=0;
        b64 = realloc(b64, len + l + 1);
        memcpy(b64+len, line, l);
        len += l;
        b64[len]=0;
    }
    fclose(f);

    size_t blob_len;
    unsigned char *blob = base64_decode(b64, &blob_len);
    free(b64);
    if(blob_len < 4) { free(blob); return 0; }

    uint16_t nb, eb;
    memcpy(&nb, blob, 2);
    memcpy(&eb, blob+2, 2);
    rsa_init_public_key(pub);
    mpz_import(pub->n, nb, 1, 1, 1, 0, blob+4);
    mpz_import(pub->e, eb, 1, 1, 1, 0, blob+4+nb);
    free(blob);
    return 1;
}

// --- PEM Import Private Key ---
int rsa_import_private_key_pem(const char *filename, RSA_PrivateKey *priv) {
    FILE *f = fopen(filename,"r");
    if(!f) return 0;
    char line[256], *b64 = NULL;
    size_t cap=0, len=0;
    while(fgets(line, sizeof(line), f)) {
        if(strstr(line,"-----")) continue;
        size_t l = strlen(line);
        while(l>0 && (line[l-1]=='\n'||line[l-1]=='\r')) line[--l]=0;
        b64 = realloc(b64, len + l + 1);
        memcpy(b64+len, line, l);
        len += l;
        b64[len]=0;
    }
    fclose(f);

    size_t blob_len;
    unsigned char *blob = base64_decode(b64, &blob_len);
    free(b64);
    if(blob_len < 4) { free(blob); return 0; }

    uint16_t nb, db;
    memcpy(&nb, blob, 2);
    memcpy(&db, blob+2, 2);
    rsa_init_private_key(priv);
    mpz_import(priv->n, nb, 1, 1, 1, 0, blob+4);
    mpz_import(priv->d, db, 1, 1, 1, 0, blob+4+nb);
    free(blob);
    return 1;
}
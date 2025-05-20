#include "crypto/rsa.h"
#include <stdio.h>

int main() {
    RSA_PublicKey pub;
    RSA_PrivateKey priv;

    rsa_init_public_key(&pub);
    rsa_init_private_key(&priv);

    rsa_generate_key_pair(&pub, &priv, 512); // 512-bit for demo only

    mpz_t plain, cipher, decrypted;
    mpz_inits(plain, cipher, decrypted, NULL);

    mpz_set_ui(plain, 123456789); // 測試用明文

    rsa_encrypt(cipher, plain, &pub);
    rsa_decrypt(decrypted, cipher, &priv);

    gmp_printf("Original:  %Zd\n", plain);
    gmp_printf("Encrypted: %Zd\n", cipher);
    gmp_printf("Decrypted: %Zd\n", decrypted);

    mpz_clears(plain, cipher, decrypted, NULL);
    rsa_clear_public_key(&pub);
    rsa_clear_private_key(&priv);

    return 0;
}

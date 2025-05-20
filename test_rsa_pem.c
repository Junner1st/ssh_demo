#include "crypto/rsa.h"
#include <stdio.h>


int main() {
    RSA_PublicKey pub1, pub2;
    RSA_PrivateKey priv1, priv2;
    rsa_init_public_key(&pub1);
    rsa_init_private_key(&priv1);
    rsa_generate_key_pair(&pub1, &priv1, 512);

    // 匯出
    rsa_export_public_key_pem("pub.pem", &pub1);
    rsa_export_private_key_pem("priv.pem", &priv1);
    printf("Exported PEM files.\n");

    // 匯入到新結構
    rsa_import_public_key_pem("pub.pem", &pub2);
    rsa_import_private_key_pem("priv.pem", &priv2);
    printf("Imported PEM files.\n");

    // 檢查一致性：比較 n,e 與 n,d
    if (mpz_cmp(pub1.n, pub2.n)==0 && mpz_cmp(pub1.e, pub2.e)==0)
        printf("Public key matches.\n");
    else
        printf("Public key MISMATCH!\n");

    if (mpz_cmp(priv1.n, priv2.n)==0 && mpz_cmp(priv1.d, priv2.d)==0)
        printf("Private key matches.\n");
    else
        printf("Private key MISMATCH!\n");

    // 清理
    rsa_clear_public_key(&pub1);
    rsa_clear_private_key(&priv1);
    rsa_clear_public_key(&pub2);
    rsa_clear_private_key(&priv2);

    return 0;
}

// ssh_demo.c
#include "ssh_demo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/sha.h>   // for SHA256
#include <stdint.h>
#include <errno.h>

/*-----------------------------------------------------------------------------
 * Helpers: send/recv exactly N bytes over a socket
 *---------------------------------------------------------------------------*/
// static int sock_send_all(int fd, const uint8_t *buf, size_t len) {
//     size_t sent = 0;
//     while (sent < len) {
//         ssize_t n = send(fd, buf + sent, len - sent, 0);
//         if (n <= 0) return 0;
//         sent += n;
//     }
//     return 1;
// }

// static int sock_recv_all(int fd, uint8_t *buf, size_t len) {
//     size_t recvd = 0;
//     while (recvd < len) {
//         ssize_t n = recv(fd, buf + recvd, len - recvd, 0);
//         if (n <= 0) return 0;
//         recvd += n;
//     }
//     return 1;
// }

static int sock_send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        printf("[sock_send_all] sent %zd bytes\n", n);
        if (n < 0) {
            if (errno == EINTR) continue; // 被 signal 中斷，重試
            perror("[sock_send_all] send failed ");
            return 0;
        }
        if (n == 0) {
            printf("[sock_send_all] connection closed\n");
            return 0; // 連線不應關閉
        }
        sent += n;
    }
    return 1;
}

static int sock_recv_all(int fd, uint8_t *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(fd, buf + recvd, len - recvd, 0);
        printf("[sock_recv_all] recv %zd bytes\n", n);
        if (n < 0) {
            if (errno == EINTR) continue; // 被 signal 中斷，重試
            perror("[sock_recv_all] recv failed ");
            return 0;
        }
        if (n == 0) {
            perror("[sock_recv_all] connection closed ");
            return 0; // 連線不應關閉
        }
        recvd += n;
    }
    return 1;
}

/*-----------------------------------------------------------------------------
 * 1) HostKey / KeyPair
 *---------------------------------------------------------------------------*/
void ssh_hostkey_init(SSH_HostKey *hk) {
    rsa_init_public_key(&hk->pub);
    rsa_init_private_key(&hk->priv);
}

int ssh_hostkey_generate(SSH_HostKey *hk, unsigned int bits) {
    rsa_generate_key_pair(&hk->pub, &hk->priv, bits);
    return 1;
}

int ssh_hostkey_load_public(const char *pub_path, SSH_HostKey *hk) {
    rsa_init_public_key(&hk->pub);
    return rsa_load_public_key(pub_path, &hk->pub);
}

int ssh_hostkey_load_private(const char *priv_path, SSH_HostKey *hk) {
    rsa_init_private_key(&hk->priv);
    return rsa_load_private_key(priv_path, &hk->priv);
}

int ssh_hostkey_save_public(const char *pub_path, const SSH_HostKey *hk) {
    return rsa_save_public_key(pub_path, &hk->pub);
}

int ssh_hostkey_save_private(const char *priv_path, const SSH_HostKey *hk) {
    return rsa_save_private_key(priv_path, &hk->priv);
}

void ssh_hostkey_clear(SSH_HostKey *hk) {
    rsa_clear_public_key(&hk->pub);
    rsa_clear_private_key(&hk->priv);
}

/*-----------------------------------------------------------------------------
 * 2) TransportLayer
 *---------------------------------------------------------------------------*/
SSH_TransportLayer* ssh_transport_new(int socket_fd) {
    printf("creating SSH_TransportLayer entity\n");
    SSH_TransportLayer *t = malloc(sizeof(SSH_TransportLayer));
    if (!t) return NULL;
    t->socket_fd = socket_fd;
    dh_init(&t->dh);
    // For demo, set small fixed DH params (p=23, g=5)
    mpz_set_ui(t->dh.p, 23);
    mpz_set_ui(t->dh.g, 5);
    memset(t->session_key, 0, 32);
    printf("SSH_TransportLayer created with socket_fd %d\n", t->socket_fd);
    return t;
}

void ssh_transport_free(SSH_TransportLayer *t) {
    if (!t) return;
    dh_free(&t->dh);
    close(t->socket_fd);
    free(t);
}

/**
 * Server‐side handshake
 */
int ssh_transport_handshake_server(SSH_TransportLayer *t,
                                   const SSH_HostKey *hk)
{
    /**
     * [V] 1) Generate server DH keypair.
     * [V] 2) Export server_pub. Sent it to client.
     * [V] 3) Use RSA private key to sign SHA256(server_pub).
     * [V] 4) Send [uint32 server_pub_len][server_pub][uint32 sig_len][sig] to client.
     * [] 5) Receive client_pub [uint32 client_pub_len][client_pub].
     * [] 6) Compute shared_secret = client_pub^priv mod p.
     * [] 7) Derive session_key = SHA256(shared_secret).
     */

    printf("[ssh_transport_handshake_server] starting handshake\n");
    // 1) Generate server DH keypair
    printf("[ssh_transport_handshake_server] generating server keypair\n");
    if (!dh_generate_keypair(&t->dh)) {
        perror("dh_generate_keypair failed\n");
        return 0;
    }

    // 2) Export server_pub
    printf("[ssh_transport_handshake_server] exporting server public key\n");
    uint8_t *server_pub = NULL;
    size_t server_pub_len = 0;
    if (!dh_export_public(&t->dh, &server_pub, &server_pub_len)) {
        perror("dh_export_public failed\n");
        return 0;
    }

    //------------ DEBUG [V]
    printf("[DEBUG] [server] &t->dh.pub: ");
    // for (int i = 0; i < server_pub_len; i++) printf("%02x", (&t->dh.pub)[i]);
    gmp_printf("%Zd\n", t->dh.pub);
    printf("\n");
    //------------

    //------------ DEBUG [V]
    printf("[DEBUG] [server] server_pub: ");
    for (int i = 0; i < server_pub_len; i++) printf("%02x", server_pub[i]);
    printf("\n");
    //------------

    // 3) Compute SHA256(server_pub)
    printf("[ssh_transport_handshake_server] computing SHA256(server_pub)\n");
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(server_pub, server_pub_len, hash);

    // //------------ DEBUG [V]
    // printf("[DEBUG] [server] hash: ");
    // for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", hash[i]);
    // printf("\n");
    // //------------


    // 4) Sign hash with RSA private: sig = hash^d mod n
    printf("[ssh_transport_handshake_server] signing hash with RSA private key...\n");
    mpz_t hash_mpz, sig_mpz;
    mpz_init(hash_mpz);
    mpz_init(sig_mpz);
    printf("[ssh_transport_handshake_server] importing hash to mpz...\n");
    // gmp_printf("priv.n = %Zd\n", hk->priv.n);
    // gmp_printf("priv.d = %Zd\n", hk->priv.d);
    mpz_import(hash_mpz, SHA256_DIGEST_LENGTH, 1, 1, 1, 0, hash);
    mpz_powm(sig_mpz, hash_mpz, hk->priv.d, hk->priv.n);
    printf("[ssh_transport_handshake_server] signature generated\n");

    // Export signature to bytes
    size_t sig_len = (mpz_sizeinbase(sig_mpz, 2) + 7) / 8;
    uint8_t *sig = malloc(sig_len);
    if (!sig) {
        mpz_clear(hash_mpz);
        mpz_clear(sig_mpz);
        free(server_pub);
        perror("malloc sig failed\n");
        return 0;
    }
    mpz_export(sig, NULL, 1, 1, 1, 0, sig_mpz);
    printf("[ssh_transport_handshake_server] signature exported\n");
    mpz_clear(hash_mpz);
    mpz_clear(sig_mpz);

    // 5) Send [uint32 server_pub_len][server_pub]
    printf("[ssh_transport_handshake_server] sending [uint32 srv_pub_len][srv_pub][uint32 sig_len][sig]...\n");
    uint32_t net_spl = htonl((uint32_t)server_pub_len);
    if (!sock_send_all(t->socket_fd, (uint8_t*)&net_spl, 4)) goto fail;
    if (!sock_send_all(t->socket_fd, server_pub, server_pub_len)) goto fail;
    //    [uint32 sig_len][sig]
    uint32_t net_sigl = htonl((uint32_t)sig_len);
    if (!sock_send_all(t->socket_fd, (uint8_t*)&net_sigl, 4)) goto fail;
    if (!sock_send_all(t->socket_fd, sig, sig_len)) goto fail;

    // //------------ DEBUG V
    // printf("[DEBUG] [server] server_pub: ");
    // for (int i = 0; i < server_pub_len; i++) printf("%02x", server_pub[i]);
    // printf("\n");
    // printf("[DEBUG] [server] sig: ");
    // for (int i = 0; i < sig_len; i++) printf("%02x", sig[i]);
    // printf("\n");
    // //------------

    // 6) Receive [uint32 client_pub_len][client_pub]
    printf("[ssh_transport_handshake_server] receiving client_pub_len and client_pub...\n");
    uint32_t net_cpl;
    if (!sock_recv_all(t->socket_fd, (uint8_t*)&net_cpl, 4)) goto fail;
    uint32_t client_pub_len = ntohl(net_cpl);
    uint8_t *client_pub = malloc(client_pub_len);
    if (!client_pub) goto fail;
    if (!sock_recv_all(t->socket_fd, client_pub, client_pub_len)) {
        free(client_pub);
        goto fail;
    }

    // printf("[DEBUG] [server] client_pub: ");
    // for (int i = 0; i < client_pub_len; i++) printf("%02x", client_pub[i]);
    // printf("\n");

    // 7) Compute shared_secret = client_pub^priv mod p
    printf("[ssh_transport_handshake_server] computing shared_secret\n");
    mpz_t client_pub_mpz, shared_mpz;
    mpz_init(client_pub_mpz);
    mpz_init(shared_mpz);
    mpz_import(client_pub_mpz, client_pub_len, 1, 1, 1, 0, client_pub);
    mpz_powm(shared_mpz, client_pub_mpz, t->dh.priv, t->dh.p);

    // //------------ DEBUG [-]
    // printf("[DEBUG] [server] : ");
    // printf("small a = ");
    // gmp_printf("%Zd\n", t->dh.priv);
    // //------------

    //------------ DEBUG []
    printf("[DEBUG] [server] client_pub_mpz: ");
    gmp_printf("%Zd\n", client_pub_mpz);
    printf("[DEBUG] [server] t->dh.priv: ");
    gmp_printf("%Zd\n", t->dh.priv);
    printf("[DEBUG] [server] t->dh.p: ");
    gmp_printf("%Zd\n", t->dh.p);
    //------------

    //------------ DEBUG [x]
    printf("[DEBUG] [server] shared_mpz: ");
    gmp_printf("%Zd\n", shared_mpz);
    //------------

    // Export shared to bytes
    size_t shared_len = (mpz_sizeinbase(shared_mpz, 2) + 7) / 8;
    uint8_t *shared = malloc(shared_len);
    if (!shared) {
        mpz_clear(client_pub_mpz);
        mpz_clear(shared_mpz);
        free(client_pub);
        goto fail;
    }
    mpz_export(shared, NULL, 1, 1, 1, 0, shared_mpz);

    // Derive session_key = SHA256(shared)
    SHA256(shared, shared_len, t->session_key);

    printf("[DEBUG] [server] session_key: ");
    for (int i = 0; i < 32; i++) printf("%02x", t->session_key[i]);
    printf("\n");
    printf("[DEBUG] [server] shared: ");
    for (int i = 0; i < shared_len; i++) printf("%02x", shared[i]);
    printf("\n");

    // Cleanup
    printf("[ssh_transport_handshake_server] handshake complete\n");
    mpz_clear(client_pub_mpz);
    mpz_clear(shared_mpz);
    free(shared);
    free(client_pub);
    free(server_pub);
    free(sig);
    return 1;

fail:
    perror("send/recv failed\n");
    free(server_pub);
    free(sig);
    return 0;
}

/**
 * Client‐side handshake
 */
int ssh_transport_handshake_client(SSH_TransportLayer *t,
                                   const SSH_HostKey *server_key)
{
    /**
     * [V] 1) Receive [uint32 srv_pub_len][srv_pub][uint32 sig_len][sig] from socket.
     * [V] 2) Compute SHA256(srv_pub) → verify sig with server_key->pub.
     * [] 3) Import srv_pub into t->dh.pub.
     * [] 4) Generate new t->dh keypair, export client_pub.
     * [] 5) Compute shared_secret = (srv_pub)^priv mod p.
     * [] 6) session_key = SHA256(shared_secret).
     * [] 7) Send [uint32 client_pub_len][client_pub].
     */

    // 1) Receive [uint32 srv_pub_len][srv_pub][uint32 sig_len][sig]
    uint32_t net_spl;
    if (!sock_recv_all(t->socket_fd, (uint8_t*)&net_spl, 4)) {
        printf("recv server_pub_len failed\n");
        return 0;
    }
    uint32_t server_pub_len = ntohl(net_spl);
    printf("[DEBUG] [client] [ck0] server_pub_len: %u\n", server_pub_len);

    uint8_t *server_pub = malloc(server_pub_len);
    if (!server_pub) {
        printf("malloc server_pub failed\n");
        return 0;
    }
    if (!sock_recv_all(t->socket_fd, server_pub, server_pub_len)) {
        free(server_pub);
        printf("recv server_pub failed\n");
        return 0;
    }
    uint32_t net_sigl;
    if (!sock_recv_all(t->socket_fd, (uint8_t*)&net_sigl, 4)) {
        free(server_pub);
        printf("recv sig_len failed\n");
        return 0;
    }
    uint32_t sig_len = ntohl(net_sigl);
    uint8_t *sig = malloc(sig_len);
    if (!sig) {
        free(server_pub);
        printf("malloc sig failed\n");
        return 0;
    }
    if (!sock_recv_all(t->socket_fd, sig, sig_len)) {
        free(server_pub);
        free(sig);
        printf("recv sig failed\n");
        return 0;
    }

    // //------------ DEBUG V
    // printf("[DEBUG] [client] server_pub: ");
    // for (int i = 0; i < server_pub_len; i++) printf("%02x", server_pub[i]);
    // printf("\n");
    // printf("[DEBUG] [client] sig: ");
    // for (int i = 0; i < sig_len; i++) printf("%02x", sig[i]);
    // printf("\n");
    // //------------

    // 2) Compute SHA256(server_pub)
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(server_pub, server_pub_len, hash);

    // 3) Verify signature: compute decrypted = sig^e mod n, compare to hash
    mpz_t sig_mpz, dec_mpz, hash_mpz;
    mpz_init(sig_mpz);
    mpz_init(dec_mpz);
    mpz_init(hash_mpz);
    mpz_import(sig_mpz, sig_len, 1, 1, 1, 0, sig);
    mpz_powm(dec_mpz, sig_mpz, server_key->pub.e, server_key->pub.n);
    mpz_import(hash_mpz, SHA256_DIGEST_LENGTH, 1, 1, 1, 0, hash);

    if (mpz_cmp(dec_mpz, hash_mpz) != 0) {
        // signature invalid
        mpz_clear(sig_mpz);
        mpz_clear(dec_mpz);
        mpz_clear(hash_mpz);
        free(server_pub);
        free(sig);

        printf("signature verification failed\n");
        return 0;
    }

    // //------------ DEBUG [V]
    // printf("[DEBUG] [client] hash: ");
    // for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", hash[i]);
    // printf("\n");
    // //------------

    mpz_clear(sig_mpz);
    mpz_clear(dec_mpz);
    mpz_clear(hash_mpz);


    
    // 4) Import server_pub into DH context
    mpz_import(t->dh.pub, server_pub_len, 1, 1, 1, 0, server_pub);
    free(sig);
    
    //------------ DEBUG []
    printf("[DEBUG] [client] t->dh.pub: ");
    // for (int i = 0; i < server_pub_len; i++) printf("%02x", server_pub[i]);
    // printf("\n");
    gmp_printf("%Zd\n", t->dh.pub);
    printf("[DEBUG] [client] server_pub_len: %u\n", server_pub_len);
    //------------

    // free(server_pub);
    // 5) Generate client DH keypair
    if (!dh_generate_keypair(&t->dh)) {
        printf("dh_generate_keypair failed\n");
        return 0;
    }


    /// looks not right : t->dh.pub should be server_pub?
    uint8_t *client_pub = NULL;
    size_t client_pub_len = 0;
    if (!dh_export_public(&t->dh, &client_pub, &client_pub_len)) {
        printf("dh_export_public failed\n");
        return 0;
    }
    ///---------------

    // 6) Compute shared_secret = server_pub^priv mod p
    // (DH context already has server_pub in t->dh.pub)
    uint8_t *shared = NULL;
    size_t shared_len = 0;
    // if (!dh_compute_shared(&t->dh, (const uint8_t *)NULL, 0, &shared, &shared_len)) {
    //     // Note: dh_compute_shared expects peer buffer; but we loaded server_pub directly into t->dh.pub,
    //     // so we compute shared manually:
    //     mpz_t shared_mpz;
    //     mpz_init(shared_mpz);
    //     mpz_powm(shared_mpz, t->dh.pub, t->dh.priv, t->dh.p);
    //     shared_len = (mpz_sizeinbase(shared_mpz, 2) + 7) / 8;
    //     shared = malloc(shared_len);
    //     if (!shared) {
    //         mpz_clear(shared_mpz);
    //         free(client_pub);
    //         printf("malloc shared failed\n");
    //         return 0;
    //     }
    //     mpz_export(shared, NULL, 1, 1, 1, 0, shared_mpz);
    //     mpz_clear(shared_mpz);
    // }
    mpz_t shared_mpz, server_pub_mpz;
    mpz_init(shared_mpz);
    mpz_init(server_pub_mpz);
    // mpz_import(server_pub_mpz, server_pub_len, 1, 1, 1, 0, t->dh.pub);
    mpz_import(server_pub_mpz, server_pub_len, 1, 1, 1, 0, server_pub);
    mpz_powm(shared_mpz, server_pub_mpz, t->dh.priv, t->dh.p);
    //------------ DEBUG []
    // printf("[DEBUG] [client] server_pub_len: %u\n", server_pub_len);
    printf("[DEBUG] [client] t->dh.pub: ");
    gmp_printf("%Zd\n", t->dh.pub);
    printf("[DEBUG] [client] server_pub_mpz: ");
    gmp_printf("%Zd\n", server_pub_mpz);
    printf("[DEBUG] [client] t->dh.priv: ");
    gmp_printf("%Zd\n", t->dh.priv);
    printf("[DEBUG] [client] t->dh.p: ");
    gmp_printf("%Zd\n", t->dh.p);
    //------------


    //------------ DEBUG [x]
    printf("[DEBUG] [client] shared_mpz: ");
    gmp_printf("%Zd\n", shared_mpz);
    //------------


    shared_len = (mpz_sizeinbase(shared_mpz, 2) + 7) / 8;
    shared = malloc(shared_len);
    if (!shared) {
        mpz_clear(shared_mpz);
        mpz_clear(server_pub_mpz);
        free(client_pub);
        printf("malloc shared failed\n");
        return 0;
    }
    mpz_export(shared, NULL, 1, 1, 1, 0, shared_mpz);
    mpz_clear(shared_mpz);
    mpz_clear(server_pub_mpz);

    //------------ DEBUG []
    printf("[DEBUG] [client] : ");
    printf("small b = ");
    gmp_printf("%Zd\n", t->dh.priv);
    //------------

    // 7) Derive session_key = SHA256(shared)
    SHA256(shared, shared_len, t->session_key);
    
    printf("[DEBUG] [client] session_key: ");
    for (int i = 0; i < 32; i++) printf("%02x", t->session_key[i]);
    printf("\n");
    printf("[DEBUG] [client] shared: ");
    for (int i = 0; i < shared_len; i++) printf("%02x", shared[i]);
    printf("\n");
    
    free(shared);

    // 8) Send [uint32 client_pub_len][client_pub]
    uint32_t net_cpl = htonl((uint32_t)client_pub_len);
    if (!sock_send_all(t->socket_fd, (uint8_t*)&net_cpl, 4)) {
        free(client_pub);
        printf("send client_pub_len failed\n");
        return 0;
    }
    if (!sock_send_all(t->socket_fd, client_pub, client_pub_len)) {
        free(client_pub);
        printf("send client_pub failed\n");
        return 0;
    }
    free(client_pub);
    return 1;
}

/**
 * Send a framed packet:
 *   [uint32 payload_len][payload][uint32 mac_len][mac]
 *   payload = [msg_type||data]
 */
int ssh_transport_send(SSH_TransportLayer *t,
                       uint8_t msg_type,
                       const uint8_t *data,
                       size_t data_len)
{
    // Build payload
    size_t payload_len = 1 + data_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) return 0;
    payload[0] = msg_type;
    if (data_len > 0) memcpy(payload + 1, data, data_len);

    // Compute HMAC‐SHA256(session_key, payload)
    uint8_t mac[SHA256_DIGEST_LENGTH];
    unsigned int mac_len = 0;
    dh_hmac_sign(t->session_key, 32, payload, payload_len, mac, &mac_len);

    // Send payload_len
    uint32_t net_pl = htonl((uint32_t)payload_len);
    printf("[ssh_transport_send] sending payload_len %u\n", payload_len);
    if (!sock_send_all(t->socket_fd, (uint8_t*)&net_pl, 4)) {
        free(payload);
        return 0;
    }


    // Send payload
    printf("[ssh_transport_send] sending payload %u\n", payload);
    if (!sock_send_all(t->socket_fd, payload, payload_len)) {
        free(payload);
        return 0;
    }


    // Send mac_len
    uint32_t net_ml = htonl(mac_len);
    printf("[ssh_transport_send] sending mac_len %u\n", mac_len);
    if (!sock_send_all(t->socket_fd, (uint8_t*)&net_ml, 4)) {
        free(payload);
        return 0;
    }

    // Send mac
    printf("[ssh_transport_send] sending mac %u\n", mac);
    printf("[ssh_transport_send] sending mac: ");
    for (unsigned int i = 0; i < mac_len; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");

    if (!sock_send_all(t->socket_fd, mac, mac_len)) {
        free(payload);
        return 0;
    }

    free(payload);
    return 1;
}

/**
 * Receive a framed packet:
 */
int ssh_transport_recv(SSH_TransportLayer *t,
                       uint8_t *out_msg_type,
                       uint8_t **out_data,
                       size_t *out_data_len)
{
    // Read payload_len
    uint32_t net_pl;
    if (!sock_recv_all(t->socket_fd, (uint8_t*)&net_pl, 4)) {
        perror("[ssh_transport_recv] recv payload_len failed ");
        return 0;
    }
    uint32_t payload_len = ntohl(net_pl);
    if (payload_len == 0) {
        perror("[ssh_transport_recv] invalid payload_len ");
        return 0;
    }

    // Read payload
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        perror("[ssh_transport_recv] malloc payload failed ");
        return 0;
    }
    if (!sock_recv_all(t->socket_fd, payload, payload_len)) {
        free(payload);
        perror("[ssh_transport_recv] recv payload failed ");
        return 0;
    }

    // Read mac_len
    uint32_t net_ml;
    if (!sock_recv_all(t->socket_fd, (uint8_t*)&net_ml, 4)) {
        free(payload);
        perror("[ssh_transport_recv] recv mac_len failed ");
        return 0;
    }
    uint32_t mac_len = ntohl(net_ml);
    if (mac_len != SHA256_DIGEST_LENGTH) {
        printf("[ssh_transport_recv] invalid mac_len %u\n", mac_len);
        free(payload);
        return 0;
    }

    // Read mac
    uint8_t *mac = malloc(mac_len);
    if (!mac) {
        free(payload);
        perror("[ssh_transport_recv] malloc mac failed ");
        return 0;
    }
    if (!sock_recv_all(t->socket_fd, mac, mac_len)) {
        free(payload);
        free(mac);
        perror("[ssh_transport_recv] recv mac failed ");
        return 0;
    }

    // Verify HMAC
    uint8_t expected[SHA256_DIGEST_LENGTH];
    unsigned int expected_len = 0;
    unsigned int result_is_not_null = dh_hmac_sign(t->session_key, 32, payload, payload_len, expected, &expected_len);
    if (result_is_not_null == 0) {
        free(payload);
        free(mac);
        printf("[ssh_transport_recv] HMAC sign failed\n");
        return 0;
    }
    if (expected_len != mac_len) {
        free(payload);
        free(mac);
        printf("[ssh_transport_recv] HMAC length mismatch\n");
        return 0;
    }
    if (memcmp(expected, mac, mac_len) != 0) {  // if the returned value of memacmp isn't equals to 0, that means mismatch
        free(payload);
        free(mac);
        printf("[ssh_transport_recv] HMAC verification failed\n");
        return 0;
    }
    free(mac);

    // Extract msg_type and data
    *out_msg_type = payload[0];
    *out_data_len = payload_len - 1;
    if (*out_data_len > 0) {
        *out_data = malloc(*out_data_len);
        if (!*out_data) {
            free(payload);
            printf("[ssh_transport_recv] malloc out_data failed\n");
            return 0;
        }
        memcpy(*out_data, payload + 1, *out_data_len);
    } else {
        *out_data = NULL;
    }

    free(payload);
    return 1;
}

/*-----------------------------------------------------------------------------
 * 3) User Authentication
 *---------------------------------------------------------------------------*/
int ssh_auth_password(SSH_TransportLayer *t,
                      const char *username,
                      const char *password)
{
    // //-------------- DEBUG [V]
    // printf("[DEBUG] [ssh_auth_password] username: %s\n", username);
    // printf("[DEBUG] [ssh_auth_password] password: %s\n", password);
    // //--------------

    size_t ulen = strlen(username);
    size_t plen = strlen(password);
    // //-------------- DEBUG [V]
    // printf("[DEBUG] [ssh_auth_password] username length: %d\n", (int)ulen);
    // printf("[DEBUG] [ssh_auth_password] password length: %d\n", (int)plen);
    // //--------------

    size_t msg_len = 12 + ulen + plen; // "AUTH_PASS:" + username + ":" + password + '\0'
    char *msg = malloc(msg_len);
    if (!msg) {
        perror("[ssh_auth_password] malloc msg failed ");
        return 0;
    }
    snprintf(msg, msg_len, "AUTH_PASS:%s:%s", username, password);
    printf("[ssh_auth_password] [client] sending msg: %s\n", msg);

    if (!ssh_transport_send(t, SSH_MSG_AUTH_REQUEST,
                            (uint8_t*)msg, strlen(msg))) {
        perror("[ssh_auth_password] send failed ");
        free(msg);
        return 0;
    }
    free(msg);

    // Wait for response
    uint8_t resp_type;
    uint8_t *resp_data = NULL;
    size_t resp_len = 0;
    if (!ssh_transport_recv(t, &resp_type, &resp_data, &resp_len)) {
        perror("[ssh_auth_password] recv failed ");
        return 0;
    }
    int ok = 0;
    if (resp_type == SSH_MSG_AUTH_RESPONSE && resp_len == 2
        && strncmp((char*)resp_data, "OK", 2) == 0) {
        ok = 1;
        printf("[ssh_auth_password] authentication successful\n");
    }
    free(resp_data);
    return ok;
}

int ssh_auth_publickey(SSH_TransportLayer *t,
                       const char *username,
                       const RSA_PrivateKey *client_priv)
{
    // Not implemented in demo
    return 0;
}

/*-----------------------------------------------------------------------------
 * 4) Channel / Exec Command
 *---------------------------------------------------------------------------*/
int ssh_channel_send_exec(SSH_TransportLayer *t,
                          const char *command)
{
    printf("[ssh_channel_send_exec] [client] sending command: %s\n", command);
    size_t cmd_len = strlen(command);
    size_t msg_len = 6 + cmd_len;  // "EXEC:" + command + '\0'
    char *msg = malloc(msg_len);
    if (!msg) {
        perror("[ssh_channel_send_exec] malloc msg failed ");
        return 0;
    }
    snprintf(msg, msg_len, "EXEC:%s", command);
    int ok = ssh_transport_send(t, SSH_MSG_EXEC_REQUEST,
                                (uint8_t*)msg, strlen(msg));
    free(msg);
    return ok;
}

int ssh_channel_recv_exec_response(SSH_TransportLayer *t,
                                   uint8_t **out_data,
                                   size_t *out_len)
{
    uint8_t msg_type;
    uint8_t *data = NULL;
    size_t data_len = 0;
    if (!ssh_transport_recv(t, &msg_type, &data, &data_len)) return 0;
    if (msg_type != SSH_MSG_EXEC_RESPONSE) {
        free(data);
        return 0;
    }
    *out_data = data;
    *out_len = data_len;
    return 1;
}

int ssh_channel_send_close(SSH_TransportLayer *t) {
    return ssh_transport_send(t, SSH_MSG_CHANNEL_CLOSE, NULL, 0);
}

/*-----------------------------------------------------------------------------
 * 5) Session (Client‐side)
 *---------------------------------------------------------------------------*/
SSH_Session* ssh_session_new(int socket_fd) {
    SSH_Session *sess = malloc(sizeof(SSH_Session));
    if (!sess) return NULL;
    sess->transport = ssh_transport_new(socket_fd);
    return sess;
}

void ssh_session_free(SSH_Session *sess) {
    if (!sess) return;
    if (sess->transport) {
        ssh_transport_free(sess->transport);
    }
    free(sess);
}

int ssh_session_connect(SSH_Session *sess,
                        const SSH_HostKey *server_key,
                        const char *username,
                        const char *password)
{
    if (!ssh_transport_handshake_client(sess->transport, server_key)) {
        printf("Handshake failed\n");
        return 0;
    }
    if (!ssh_auth_password(sess->transport, username, password)) {
        printf("Authentication failed\n");
        return 0;
    }
    return 1;
}

int ssh_session_run_command(SSH_Session *sess,
                            const char *command,
                            char **out_data,
                            size_t *out_len)
{
    if (!ssh_channel_send_exec(sess->transport, command))
        return 0;

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    if (!ssh_channel_recv_exec_response(sess->transport, &resp, &resp_len))
        return 0;

    *out_data = (char*)resp;
    *out_len = resp_len;
    return 1;
}

int ssh_session_close(SSH_Session *sess) {
    if (!sess || !sess->transport) return 0;
    ssh_channel_send_close(sess->transport);
    ssh_transport_free(sess->transport);
    sess->transport = NULL;
    return 1;
}

/*-----------------------------------------------------------------------------
 * 6) Server (Demo)
 *---------------------------------------------------------------------------*/
SSH_Server* ssh_server_new(int listen_fd) {
    SSH_Server *srv = malloc(sizeof(SSH_Server));
    if (!srv) return NULL;
    srv->listen_fd = listen_fd;
    ssh_hostkey_init(&srv->hostkey);
    return srv;
}

void ssh_server_free(SSH_Server *srv) {
    if (!srv) return;
    ssh_hostkey_clear(&srv->hostkey);
    close(srv->listen_fd);
    free(srv);
}

int ssh_server_start(SSH_Server *srv) {
    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(srv->listen_fd, (struct sockaddr*)&cli_addr, &cli_len);
        if (client_fd < 0) {
            perror("[Server] accept");
            continue;
        }
        printf("[Server] Accepted connection from %s:%d\n",
               inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
        pid_t pid = fork();
        if (pid < 0) {
            perror("[Server] fork");
            close(client_fd);
            continue;
        }
        if (pid == 0) {
            // Child: handle connection
            close(srv->listen_fd);
            printf("[Server] Child process %d handling connection\n", getpid());
            ssh_server_handle_connection(srv, client_fd);
            _exit(0);
        } else {
            // Parent
            close(client_fd);
            waitpid(-1, NULL, WNOHANG);
        }
    }
    return 1;
}

int ssh_server_handle_connection(SSH_Server *srv, int client_fd) {
    SSH_TransportLayer *t = ssh_transport_new(client_fd);
    if (!t) {
        printf("[Server] Failed to create transport layer entity\n");
        close(client_fd);
        return 0;
    }

    // 1) DH handshake + RSA sign
    int handshake_ok = ssh_transport_handshake_server(t, &srv->hostkey);
    printf("[Server] DH Handshake + RSA sign %s\n", handshake_ok ? "OK" : "FAIL");
    if (!handshake_ok) {
        ssh_transport_free(t);
        printf("[Server] Handshake failed\n");
        close(client_fd);
        return 0;
    }

    printf("[Server] Starting authentication...\n");
    // 2) Receive AUTH_REQUEST
    uint8_t msg_type;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    int ssh_transport_recv_ok = ssh_transport_recv(t, &msg_type, &payload, &payload_len);
    printf("[Server] payload_len: %zu\n", payload_len);
    printf("[Server] Received AUTH_REQUEST: %s\n", ssh_transport_recv_ok ? "OK" : "FAIL");
    if (!ssh_transport_recv_ok) {
        ssh_transport_free(t);
        return 0;
    }
    int auth_ok = 0;

    if (msg_type == SSH_MSG_AUTH_REQUEST && payload) {
        printf("[Server] AUTH_REQUEST payload: %s\n", payload);
        // payload[payload_len] = '\0';
        // Format: "AUTH_PASS:username:password"
        if (payload_len < 11) { // 至少要有 "AUTH_PASS::"
            printf("[Server] AUTH_PASS payload too short\n");
        } else if (strncmp((char*)payload, "AUTH_PASS:", 10) == 0) {
            // 找到 username 和 password 的分隔點
            char *user_start = (char*)payload + 10;
            char *colon = memchr(user_start, ':', payload_len - 10);
            if (colon) {
                size_t user_len = colon - user_start;
                size_t pass_len = payload_len - 10 - user_len - 1;
                char username[128], password[128];
                snprintf(username, sizeof(username), "%.*s", (int)user_len, user_start);
                snprintf(password, sizeof(password), "%.*s", (int)pass_len, colon + 1);
                printf("[Server] AUTH_PASS: username=%s, password=%s\n", username, password);
                if (strcmp(username, "testuser") == 0 && strcmp(password, "testpass") == 0) {
                    auth_ok = 1;
                } else {
                    printf("[Server] AUTH_PASS failed: invalid username/password\n");
                }
            }
        }
    }
    free(payload);

    // 3) Send AUTH_RESPONSE
    const char *resp = auth_ok ? "OK" : "FAIL";
    ssh_transport_send(t, SSH_MSG_AUTH_RESPONSE, (uint8_t*)resp, strlen(resp));
    if (!auth_ok) {
        ssh_transport_free(t);
        return 0;
    }

    // 4) Receive EXEC_REQUEST
    if (!ssh_transport_recv(t, &msg_type, &payload, &payload_len)) {
        ssh_transport_free(t);
        return 0;
    }
    if (msg_type != SSH_MSG_EXEC_REQUEST || !payload) {
        free(payload);
        ssh_transport_free(t);
        return 0;
    }
    payload[payload_len] = '\0';
    if (strncmp((char*)payload, "EXEC:", 5) != 0) {
        free(payload);
        ssh_transport_free(t);
        return 0;
    }
    char *cmd = strdup((char*)payload + 5);
    free(payload);

    // 5) Execute command with popen
    FILE *fp = popen(cmd, "r");
    free(cmd);
    if (!fp) {
        const char *err = "ERROR";
        ssh_transport_send(t, SSH_MSG_EXEC_RESPONSE, (uint8_t*)err, strlen(err));
        ssh_transport_free(t);
        return 0;
    }
    // Read stdout
    char buffer[1024];
    size_t total = 0;
    char *outbuf = NULL;
    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strlen(buffer);
        outbuf = realloc(outbuf, total + len);
        memcpy(outbuf + total, buffer, len);
        total += len;
    }
    pclose(fp);

    // 6) Send EXEC_RESPONSE
    if (total == 0) {
        ssh_transport_send(t, SSH_MSG_EXEC_RESPONSE, NULL, 0);
    } else {
        ssh_transport_send(t, SSH_MSG_EXEC_RESPONSE, (uint8_t*)outbuf, total);
        free(outbuf);
    }

    // 7) Close transport
    ssh_transport_free(t);
    return 1;
}

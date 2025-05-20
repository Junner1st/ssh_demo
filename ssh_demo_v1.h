// ssh_demo.h
#ifndef SSH_DEMO_H
#define SSH_DEMO_H

#include <stddef.h>
#include <stdint.h>
#include "crypto/rsa.h"
#include "crypto/diffie_hellman.h"

// -----------------------------------------------------------------------------
// HostKey / KeyPair
// -----------------------------------------------------------------------------
typedef struct {
    RSA_PublicKey pub;
    RSA_PrivateKey priv;
} SSH_HostKey;

int  ssh_hostkey_generate(SSH_HostKey *hk, unsigned int bits);
// int  ssh_hostkey_load(const char *pub_path, const char *priv_path, SSH_HostKey *hk);
int ssh_hostkey_load_private(const char *priv_path, SSH_HostKey *hk);
int ssh_hostkey_load_public(const char *pub_path, SSH_HostKey *hk);
// int  ssh_hostkey_save(const char *pub_path, const char *priv_pjath, const SSH_HostKey *hk);
void ssh_hostkey_clear(SSH_HostKey *hk);

// -----------------------------------------------------------------------------
// TransportLayer
// -----------------------------------------------------------------------------
typedef struct SSH_TransportLayer SSH_TransportLayer;

SSH_TransportLayer* ssh_transport_new(int socket_fd);
void                ssh_transport_free(SSH_TransportLayer *t);
int                 ssh_transport_handshake(SSH_TransportLayer *t,
                                              const SSH_HostKey *server_key,
                                              RSA_PublicKey *client_pub,
                                              RSA_PrivateKey *client_priv);
int                 ssh_transport_send(SSH_TransportLayer *t,
                                        uint8_t msg_type,
                                        const uint8_t *payload,
                                        size_t payload_len);
int                 ssh_transport_recv(SSH_TransportLayer *t,
                                        uint8_t *msg_type,
                                        uint8_t **payload,
                                        size_t *payload_len);

// -----------------------------------------------------------------------------
// Key Exchange (Diffie–Hellman)
// -----------------------------------------------------------------------------
typedef DH_Context SSH_KEX;

SSH_KEX* ssh_kex_new(void);
void     ssh_kex_free(SSH_KEX *k);
int      ssh_kex_init_client(SSH_KEX *k, uint8_t **pub_blob, size_t *pub_len);
int      ssh_kex_init_server(SSH_KEX *k, const uint8_t *client_blob, size_t client_len,
                             uint8_t **pub_blob, size_t *pub_len);
int      ssh_kex_compute_shared(SSH_KEX *k,
                                const uint8_t *peer_blob, size_t peer_len,
                                uint8_t **shared_secret, size_t *secret_len);

// -----------------------------------------------------------------------------
// User Authentication
// -----------------------------------------------------------------------------
typedef enum {
    SSH_AUTH_SUCCESS = 0,
    SSH_AUTH_FAILURE = 1,
} SSH_AuthResult;

int ssh_auth_password(SSH_TransportLayer *t,
                      const char *username,
                      const char *password);

int ssh_auth_publickey(SSH_TransportLayer *t,
                       const char *username,
                       const RSA_PrivateKey *client_priv);

// -----------------------------------------------------------------------------
// Channel
// -----------------------------------------------------------------------------
typedef struct {
    uint32_t channel_id;
    uint32_t window_size;
    // other flow-control fields...
} SSH_Channel;

int ssh_channel_open_shell(SSH_TransportLayer *t, SSH_Channel *ch);
int ssh_channel_send_data(SSH_TransportLayer *t,
                          const SSH_Channel *ch,
                          const uint8_t *data,
                          size_t len);
int ssh_channel_recv_data(SSH_TransportLayer *t,
                          SSH_Channel *ch,
                          uint8_t **data,
                          size_t *len);
int ssh_channel_close(SSH_TransportLayer *t, const SSH_Channel *ch);

// -----------------------------------------------------------------------------
// Session (client-side)
// -----------------------------------------------------------------------------
typedef struct {
    SSH_TransportLayer *transport;
    SSH_KEX            *kex;
    SSH_Channel        channel;
} SSH_Session;

SSH_Session* ssh_session_new(int socket_fd);
void         ssh_session_free(SSH_Session *sess);
int          ssh_session_connect(SSH_Session *sess,
                                 const SSH_HostKey *server_key,
                                 const RSA_PublicKey *client_pub,
                                 const RSA_PrivateKey *client_priv,
                                 const char *username,
                                 const char *password_or_keypath);
int          ssh_session_run_command(SSH_Session *sess,
                                     const char *command,
                                     char **output,
                                     size_t *out_len);
int          ssh_session_close(SSH_Session *sess);

// -----------------------------------------------------------------------------
// Server (demo)
// -----------------------------------------------------------------------------
typedef struct {
    int               listen_fd;
    SSH_HostKey       hostkey;
} SSH_Server;

SSH_Server* ssh_server_new(int listen_fd);
void        ssh_server_free(SSH_Server *srv);
int         ssh_server_start(SSH_Server *srv);
int         ssh_server_handle_connection(SSH_Server *srv, int client_fd);

#endif // SSH_DEMO_H

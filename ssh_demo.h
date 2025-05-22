// ssh_demo.h
#ifndef SSH_DEMO_H
#define SSH_DEMO_H

#include <stddef.h>
#include <stdint.h>
#include "crypto/rsa.h"
#include "crypto/diffie_hellman.h"

/*-----------------------------------------------------------------------------
 * SSH Demo: Header file defining core structures and APIs for a minimal SSH‐like
 * system. Uses:
 *   - RSA (from rsa.h) for host key signatures
 *   - Ephemeral Diffie–Hellman (from diffie_hellman.h) for shared secret
 *   - HMAC‐SHA256 (via dh_hmac_sign / dh_hmac_verify) for packet integrity
 * 
 * Flow overview:
 *   1. Server and client perform DH handshake:
 *        • Server: generate DH keypair, sign DH public with its RSA priv, send both
 *        • Client: verify server’s RSA signature on DH public, send its DH public
 *        • Both derive shared secret → SHA256 → session_key
 *   2. On top of that, every packet is framed as:
 *        [uint32 payload_len][payload][uint32 mac_len][mac]
 *     where payload = [msg_type (1 byte) || data_bytes], mac = HMAC(session_key, payload)
 *   3. After handshake, client does password auth or exec‐command; server verifies.
 *----------------------------------------------------------------------------*/

/*===========================================================================
 * 1) HostKey / KeyPair
 *===========================================================================*/
typedef struct {
    RSA_PublicKey  pub;     // server’s RSA public key
    RSA_PrivateKey priv;    // server’s RSA private key
} SSH_HostKey;

/**
 * Initialize a fresh (empty) host key object.
 *  - User must call ssh_hostkey_clear() when done.
 */
void ssh_hostkey_init(SSH_HostKey *hk);

/**
 * Generate a new RSA keypair of 'bits' size, store in hk->pub and hk->priv.
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_hostkey_generate(SSH_HostKey *hk, unsigned int bits);

/**
 * Load an existing RSA public key from 'pub_path' into hk->pub.
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_hostkey_load_public(const char *pub_path, SSH_HostKey *hk);

/**
 * Load an existing RSA private key from 'priv_path' into hk->priv.
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_hostkey_load_private(const char *priv_path, SSH_HostKey *hk);

/**
 * Save the RSA public key in hk->pub to 'pub_path' (text, hex).
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_hostkey_save_public(const char *pub_path, const SSH_HostKey *hk);

/**
 * Save the RSA private key in hk->priv to 'priv_path' (text, hex).
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_hostkey_save_private(const char *priv_path, const SSH_HostKey *hk);

/**
 * Free all GMP resources inside hk->pub and hk->priv.
 */
void ssh_hostkey_clear(SSH_HostKey *hk);


/*===========================================================================
 * 2) TransportLayer (framing + DH handshake + HMAC)
 *===========================================================================*/
/* Message types (1‐byte) used in payload[0] */
enum {
    SSH_MSG_DH_CLIENT_PUB    = 10,   // client → server, ephemeral DH public
    SSH_MSG_DH_SERVER_PUB    = 11,   // server → client, ephemeral DH public + signature
    SSH_MSG_AUTH_REQUEST     = 20,   // client → server, e.g. "AUTH_PASS:username:password"
    SSH_MSG_AUTH_RESPONSE    = 21,   // server → client, "OK" or "FAIL"
    SSH_MSG_EXEC_REQUEST     = 30,   // client → server, "EXEC:<command>"
    SSH_MSG_EXEC_RESPONSE    = 31,   // server → client, command stdout
    SSH_MSG_CHANNEL_CLOSE    = 40,   // either → other, close channel/connection
};

/**
 * Transport context: wraps a TCP socket, a DH context, and a 32‐byte session key.
 *  - Use ssh_transport_new() to allocate.
 *  - Use ssh_transport_free() when done.
 *  - Call either ssh_transport_handshake_client() or
 *    ssh_transport_handshake_server() once after socket is connected/accepted.
 */
typedef struct {
    int          socket_fd;            // underlying TCP socket
    DH_Context   dh;                   // ephemeral DH parameters & keypair
    uint8_t      session_key[32];      // SHA256(shared_secret)
} SSH_TransportLayer;

/**
 * Allocate and initialize a new transport layer bound to 'socket_fd'.
 *  - Initializes DH_Context (calls dh_init()).
 *  - Caller must call ssh_transport_free() when finished.
 */
SSH_TransportLayer* ssh_transport_new(int socket_fd);

/**
 * Free transport layer resources:
 *  - dh_free() on the DH context
 *  - closes the socket_fd
 *  - frees the struct memory
 */
void ssh_transport_free(SSH_TransportLayer *t);

/**
 * Perform client‐side DH handshake + RSA signature verification:
 *  1) Read [uint32 srv_pub_len][srv_pub][uint32 sig_len][sig] from socket.
 *  2) Compute SHA256(srv_pub) → verify sig with server_key->pub.
 *  3) Import srv_pub into t->dh.pub.
 *  4) Generate new t->dh keypair, export client_pub.
 *  5) Compute shared_secret = (srv_pub)^priv mod p.
 *  6) session_key = SHA256(shared_secret).
 *  7) Send [uint32 client_pub_len][client_pub].
 *  - Returns 1 on success, 0 on any failure.
 */
int ssh_transport_handshake_client(SSH_TransportLayer *t,
                                   const SSH_HostKey *server_key);

/**
 * Perform server‐side DH handshake + RSA signature:
 *  1) Generate t->dh keypair.
 *  2) Export server_pub; compute SHA256(server_pub); sign with hk->priv.
 *  3) Send [uint32 server_pub_len][server_pub][uint32 sig_len][sig] to client.
 *  4) Read [uint32 client_pub_len][client_pub] from socket.
 *  5) Compute shared_secret = (client_pub)^priv mod p.
 *  6) session_key = SHA256(shared_secret).
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_transport_handshake_server(SSH_TransportLayer *t,
                                   const SSH_HostKey *hk);

/**
 * Send a framed packet over the transport:
 *   [uint32 payload_len][payload][uint32 mac_len][mac]
 * where payload = [msg_type (1 byte) || data_bytes],
 * and mac = HMAC‐SHA256(session_key, payload).
 *  - msg_type: one of the SSH_MSG_* constants above.
 *  - data: pointer to data_bytes array (can be NULL if data_len=0).
 *  - data_len: length of data_bytes.
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_transport_send(SSH_TransportLayer *t,
                       uint8_t msg_type,
                       const uint8_t *data,
                       size_t data_len);

/**
 * Receive one framed packet over the transport:
 *   1) Read uint32 payload_len, then 'payload' buffer of that size.
 *   2) Read uint32 mac_len, then 'mac' buffer of that size.
 *   3) Verify mac == HMAC‐SHA256(session_key, payload).
 *   4) Extract payload[0] → *out_msg_type, payload[1..] → *out_data
 *  - Caller is responsible for freeing *out_data.
 *  - Returns 1 if MAC verified and packet parsed; 0 otherwise.
 */
int ssh_transport_recv(SSH_TransportLayer *t,
                       uint8_t *out_msg_type,
                       uint8_t **out_data,
                       size_t *out_data_len);


/*===========================================================================
 * 3) User Authentication
 *===========================================================================*/
/**
 * @brief Perform password authentication over an established transport.
 * Perform a simple “password” auth over an established transport:
 *  - Build payload string "AUTH_PASS:<username>:<password>"
 *  - Send with msg_type = SSH_MSG_AUTH_REQUEST.
 *  - Wait for SSH_MSG_AUTH_RESPONSE: payload = "OK" or "FAIL".
 *  - Return 1 if server responded "OK", 0 otherwise.
 */
int ssh_auth_password(SSH_TransportLayer *t,
                      const char *username,
                      const char *password);

/**
 * (Optional stub) Public‐key authentication, not implemented in demo.
 *  - Returns 0 (failure) always.
 */
int ssh_auth_publickey(SSH_TransportLayer *t,
                       const char *username,
                       const RSA_PrivateKey *client_priv);


/*===========================================================================
 * 4) Channel / Exec Command
 *===========================================================================*/
/**
 * Send an “exec” request:
 *  - msg_type = SSH_MSG_EXEC_REQUEST
 *  - payload = "EXEC:<command>"
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_channel_send_exec(SSH_TransportLayer *t,
                          const char *command);

/**
 * Receive an “exec response”:
 *  - Expects msg_type = SSH_MSG_EXEC_RESPONSE
 *  - Allocates *out_data and sets *out_len to byte‐length of stdout.
 *  - Caller frees *out_data.
 *  - Returns 1 on success, 0 if wrong msg_type or failure.
 */
int ssh_channel_recv_exec_response(SSH_TransportLayer *t,
                                   uint8_t **out_data,
                                   size_t *out_len);

/**
 * Send a channel‐close notification:
 *  - msg_type = SSH_MSG_CHANNEL_CLOSE
 *  - data = NULL (length=0)
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_channel_send_close(SSH_TransportLayer *t);


/*===========================================================================
 * 5) Session (Client‐side)
 *===========================================================================*/
/**
 * Represents a client‐side SSH session:
 *   - Contains a transport, performs handshake, auth, exec, teardown.
 */
typedef struct {
    SSH_TransportLayer *transport;
} SSH_Session;

/**
 * Allocate and initialize a new SSH_Session over 'socket_fd'.
 *  - Calls ssh_transport_new(socket_fd).
 */
SSH_Session* ssh_session_new(int socket_fd);

/**
 * Free the session:
 *  - Calls ssh_transport_free() if not already freed.
 *  - Frees the SSH_Session struct.
 */
void ssh_session_free(SSH_Session *sess);

/**
 * Establish an SSH session to the server:
 *  1) Call ssh_transport_handshake_client() with server_key.
 *  2) Call ssh_auth_password() with username and password.
 *  - Returns 1 if both steps succeed, 0 otherwise.
 */
int ssh_session_connect(SSH_Session *sess,
                        const SSH_HostKey *server_key,
                        const char *username,
                        const char *password);

/**
 * Run a remote command:
 *  1) Call ssh_channel_send_exec(sess->transport, command).
 *  2) Call ssh_channel_recv_exec_response(...) to read stdout.
 *  3) Store stdout in *out_data (caller frees), length in *out_len.
 *  - Returns 1 on success, 0 otherwise.
 */
int ssh_session_run_command(SSH_Session *sess,
                            const char *command,
                            char **out_data,
                            size_t *out_len);

/**
 * Close the SSH session:
 *  - Sends SSH_MSG_CHANNEL_CLOSE.
 *  - Then calls ssh_transport_free() and invalidates sess->transport.
 *  - Returns 1 on success, 0 on failure.
 */
int ssh_session_close(SSH_Session *sess);


/*===========================================================================
 * 6) Server (Demo)
 *===========================================================================*/
/**
 * Represents a minimal SSH‐server:
 *   - listen_fd: bound/listening TCP socket
 *   - hostkey: server’s RSA keypair
 */
typedef struct {
    int            listen_fd;
    SSH_HostKey    hostkey;
} SSH_Server;

/**
 * Allocate and initialize a new server struct (does not bind/listen).
 *  - User must set up 'listen_fd' (socket, bind, listen) before calling this.
 *  - Also must load or generate hostkey before starting.
 */
SSH_Server* ssh_server_new(int listen_fd);

/**
 * Free server resources:
 *  - Calls ssh_hostkey_clear() on hostkey
 *  - Closes listen_fd
 *  - Frees SSH_Server struct
 */
void ssh_server_free(SSH_Server *srv);

/**
 * Start accepting incoming connections in a loop.
 *  - For each new client_fd from accept():
 *      • fork() a child process
 *      • in child: call ssh_server_handle_connection(srv, client_fd)
 *      • in parent: close client_fd, continue loop
 *  - Returns 1 (never returns unless error).
 */
int ssh_server_start(SSH_Server *srv);

/**
 * Handle exactly one incoming client connection:
 *  1) Wrap client_fd in a SSH_TransportLayer (ssh_transport_new).
 *  2) Call ssh_transport_handshake_server() with srv->hostkey.
 *  3) Receive SSH_MSG_AUTH_REQUEST, verify credentials (e.g. only "testuser:testpass" allowed).
 *     Send SSH_MSG_AUTH_RESPONSE ("OK" or "FAIL").
 *     If "FAIL", close transport and return 0.
 *  4) Receive SSH_MSG_EXEC_REQUEST ("EXEC:<cmd>"), execute via popen(), capture stdout.
 *     Send SSH_MSG_EXEC_RESPONSE with stdout bytes.
 *  5) Close transport (ssh_transport_free) and return 1.
 */
int ssh_server_handle_connection(SSH_Server *srv, int client_fd);

#endif // SSH_DEMO_H

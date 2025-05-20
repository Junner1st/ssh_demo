// main.c
#include "ssh_demo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/**
 * Usage:
 *   ssh_demo genkey <pubfile> <privfile>
 *   ssh_demo server <listen_port> <pubfile> <privfile>
 *   ssh_demo client <server_ip> <server_port> <username> <password> <command>
 */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s genkey <pubfile> <privfile>\n"
        "  %s server <listen_port> <pubfile> <privfile>\n"
        "  %s client <server_ip> <server_port> <pubfile> <username> <password> <command>\n",
        prog, prog, prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
    }

    if (strcmp(argv[1], "genkey") == 0) {
        // ssh_demo genkey <pubfile> <privfile>
        if (argc != 4) {
            usage(argv[0]);
        }
        const char *pub_path  = argv[2];
        const char *priv_path = argv[3];

        SSH_HostKey hostkey;
        rsa_init_public_key(&hostkey.pub);
        rsa_init_private_key(&hostkey.priv);

        // Generate 1024-bit RSA key (for demo; increase in real use)
        if (!ssh_hostkey_generate(&hostkey, 1024)) {
            fprintf(stderr, "Failed to generate RSA key pair\n");
            return 1;
        }

        // Export to PEM
        if (!rsa_export_public_key_pem(pub_path, &hostkey.pub)) {
            fprintf(stderr, "Failed to save public key to %s\n", pub_path);
            return 1;
        }
        if (!rsa_export_private_key_pem(priv_path, &hostkey.priv)) {
            fprintf(stderr, "Failed to save private key to %s\n", priv_path);
            return 1;
        }

        printf("Generated RSA host key pair:\n  Public:  %s\n  Private: %s\n",
               pub_path, priv_path);

        rsa_clear_public_key(&hostkey.pub);
        rsa_clear_private_key(&hostkey.priv);
        return 0;
    }
    // else if (strcmp(argv[1], "server") == 0) {
    //     // ssh_demo server <listen_port> <pubfile> <privfile>
    //     if (argc != 5) {
    //         usage(argv[0]);
    //     }
    //     int port = atoi(argv[2]);
    //     const char *pub_path  = argv[3];
    //     const char *priv_path = argv[4];

    //     // Load host key
    //     SSH_HostKey hostkey;
    //     rsa_init_public_key(&hostkey.pub);
    //     rsa_init_private_key(&hostkey.priv);
    //     if (!rsa_load_public_key(pub_path, &hostkey.pub)) {
    //         fprintf(stderr, "Failed to load public key from %s\n", pub_path);
    //         return 1;
    //     }
    //     if (!rsa_load_private_key(priv_path, &hostkey.priv)) {
    //         fprintf(stderr, "Failed to load private key from %s\n", priv_path);
    //         return 1;
    //     }

    //     // Create listening socket
    //     int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    //     if (listen_fd < 0) {
    //         perror("socket");
    //         return 1;
    //     }
    //     int opt = 1;
    //     setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    //     struct sockaddr_in addr;
    //     memset(&addr, 0, sizeof(addr));
    //     addr.sin_family = AF_INET;
    //     addr.sin_addr.s_addr = INADDR_ANY;
    //     addr.sin_port = htons(port);

    //     if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    //         perror("bind");
    //         close(listen_fd);
    //         return 1;
    //     }
    //     if (listen(listen_fd, 5) < 0) {
    //         perror("listen");
    //         close(listen_fd);
    //         return 1;
    //     }

    //     printf("Server listening on port %d...\n", port);
    //     SSH_Server *srv = ssh_server_new(listen_fd);
    //     if (!srv) {
    //         fprintf(stderr, "Failed to allocate SSH_Server\n");
    //         close(listen_fd);
    //         return 1;
    //     }
    //     // Copy loaded hostkey into srv->hostkey
    //     rsa_clear_public_key(&srv->hostkey.pub);
    //     rsa_clear_private_key(&srv->hostkey.priv);
    //     rsa_init_public_key(&srv->hostkey.pub);
    //     rsa_init_private_key(&srv->hostkey.priv);
    //     mpz_set(srv->hostkey.pub.n, hostkey.pub.n);
    //     mpz_set(srv->hostkey.pub.e, hostkey.pub.e);
    //     mpz_set(srv->hostkey.priv.n, hostkey.priv.n);
    //     mpz_set(srv->hostkey.priv.d, hostkey.priv.d);

    //     // Start accept loop (this blocks)
    //     printf("SSH server started, waiting for handshake...\n");
    //     ssh_server_start(srv);

    //     // Cleanup (unreachable in this demo)
    //     ssh_server_free(srv);
    //     return 0;
    // }
    else if (strcmp(argv[1], "server") == 0) {
        // ssh_demo server <listen_port> <pubfile> <privfile>
        if (argc != 5) {
            usage(argv[0]);
        }
        int port = atoi(argv[2]);
        const char *pub_path  = argv[3];
        const char *priv_path = argv[4];

        // Create listening socket
        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            perror("socket");
            return 1;
        }
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(listen_fd);
            return 1;
        }
        if (listen(listen_fd, 5) < 0) {
            perror("listen");
            close(listen_fd);
            return 1;
        }

        // 建立 server 實體
        SSH_Server *srv = ssh_server_new(listen_fd);
        if (!srv) {
            fprintf(stderr, "Failed to create SSH_Server\n");
            close(listen_fd);
            return 1;
        }
        // 正確載入 hostkey
        if (!ssh_hostkey_load_public(pub_path, &srv->hostkey)) {
            fprintf(stderr, "Failed to load public key from %s\n", pub_path);
            ssh_server_free(srv);
            return 1;
        }
        if (!ssh_hostkey_load_private(priv_path, &srv->hostkey)) {
            fprintf(stderr, "Failed to load private key from %s\n", priv_path);
            ssh_server_free(srv);
            return 1;
        }

        printf("Server started on port %d\n", port);
        ssh_server_start(srv);
        ssh_server_free(srv);
        return 0;
    }
    else if (strcmp(argv[1], "client") == 0) {
        // ssh_demo client <server_ip> <server_port> <username> <password> <command>
        if (argc != 8) {
            usage(argv[0]);
        }
        const char *server_ip = argv[2];
        int server_port       = atoi(argv[3]);
        const char *pub_name  = argv[4];
        const char *username  = argv[5];
        const char *password  = argv[6];
        const char *command   = argv[7];

        // Load server's public key (for signature verification)
        SSH_HostKey server_key;
        rsa_init_public_key(&server_key.pub);
        rsa_init_private_key(&server_key.priv);  // private unused on client
        if (!rsa_load_public_key(pub_name, &server_key.pub)) {
            fprintf(stderr, "Failed to load server public key from server_pub.pem\n");
            return 1;
        }

        // Create socket and connect
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket");
            return 1;
        }
        struct sockaddr_in srv_addr;
        memset(&srv_addr, 0, sizeof(srv_addr));
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons(server_port);
        if (inet_pton(AF_INET, server_ip, &srv_addr.sin_addr) <= 0) {
            fprintf(stderr, "Invalid server IP: %s\n", server_ip);
            close(sockfd);
            return 1;
        }
        if (connect(sockfd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
            perror("connect");
            close(sockfd);
            return 1;
        }

        SSH_Session *sess = ssh_session_new(sockfd);
        if (!sess) {
            fprintf(stderr, "Failed to create SSH session\n");
            close(sockfd);
            return 1;
        }

        // Client does not need its own RSA key in this demo
        RSA_PublicKey client_pub_unused;
        RSA_PrivateKey client_priv_unused;
        rsa_init_public_key(&client_pub_unused);
        rsa_init_private_key(&client_priv_unused);

        if (!ssh_session_connect(sess,
                                 &server_key,
                                 username,
                                 password))
        {
            fprintf(stderr, "Authentication failed or handshake error\n");
            
            ssh_session_free(sess);
            return 1;
        }

        char *output = NULL;
        size_t out_len = 0;
        if (!ssh_session_run_command(sess, command, &output, &out_len)) {
            fprintf(stderr, "Failed to run command\n");
            ssh_session_free(sess);
            return 1;
        }

        printf("Command output:\n%.*s\n", (int)out_len, output);
        free(output);
        ssh_session_close(sess);
        rsa_clear_public_key(&server_key.pub);
        rsa_clear_private_key(&server_key.priv);
        return 0;
    }
    else {
        usage(argv[0]);
    }

    return 0;
}

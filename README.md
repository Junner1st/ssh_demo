# SSH DEMO


This is a demo, so the user and password are hardcoded in the code. You can find it in `ssh_demo.c` file. 

## How to run (for now)

Execution
```bash
gcc -o main.o main.c ssh_demo.c crypto/rsa.c crypto/diffie_hellman.c -lcrypto -lgmp 
```

Generate key pair
```bash
./main.o genkey <pubfile> <privfile>
```

For server side
```bash
./main.o server <listen_port> <pubfile> <privfile>
```
For example:
```bash
./main.o server 2222 pub.pem priv.pem
```

For client side
```bash
./main.o client <server_ip> <server_port> <pubfile> <username> <password> <command>
```
Foe example:
```bash
./main.o client 127.0.0.1 2222 pub.pem testuser testpass ls
```


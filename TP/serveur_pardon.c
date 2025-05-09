#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define PORT 4242
#define CLE_FILE "cle.key"
#define IV_FILE "cle.iv"
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);
    char buffer[BUFFER_SIZE] = {0};

    // Chargement clé et IV
    FILE *k = fopen(CLE_FILE, "rb");
    FILE *v = fopen(IV_FILE, "rb");
    if (!k || !v) {
        perror("Erreur ouverture cle.key / cle.iv");
        return 1;
    }

    unsigned char key[32], iv[16];
    fread(key, 1, 32, k);
    fread(iv, 1, 16, v);
    fclose(k);
    fclose(v);

    // Socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 1);
    printf("Serveur en écoute sur le port %d...\n", PORT);

    client_fd = accept(server_fd, (struct sockaddr *)&server_addr, &addr_len);
    printf("Client connecté.\n");

    // Réception du message d’excuse
    recv(client_fd, buffer, sizeof(buffer), 0);
    printf("Message reçu : %s\n", buffer);

    // Vérifie la longueur
    if (strlen(buffer) >= 20) {
        send(client_fd, key, 32, 0);
        send(client_fd, iv, 16, 0);
        printf("Excuses acceptées. Clé et IV envoyés.\n");
    } else {
        char *msg = "Excuses insuffisantes.";
        send(client_fd, msg, strlen(msg), 0);
        printf("Excuses refusées.\n");
    }

    close(client_fd);
    close(server_fd);
    return 0;
}

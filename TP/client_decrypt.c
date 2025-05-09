#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define PORT 4242
#define SERVER_IP "127.0.0.1"
#define PROJET_DIR "Projet"
#define BUF_SIZE 4096

int extension_chiffree(const char *nom) {
    return strstr(nom, ".enc") != NULL;
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void dechiffrer_fichier(const char *in_path, const char *out_path, unsigned char *key, unsigned char *iv) {
    printf("[INFO] Déchiffrement du fichier : %s\n", in_path);
    FILE *in = fopen(in_path, "rb");
    FILE *out = fopen(out_path, "wb");
    if (!in || !out) {
        perror("[ERREUR] Ouverture fichier");
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    unsigned char inbuf[BUF_SIZE], outbuf[BUF_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BUF_SIZE, in)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) handleErrors();
        fwrite(outbuf, 1, outlen, out);
    }

    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) handleErrors();
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    printf("[OK] Déchiffrement terminé pour : %s\n", in_path);
}

void parcourir_et_dechiffrer(const char *dir_path, unsigned char *key, unsigned char *iv) {
    DIR *dir = opendir(dir_path);
    struct dirent *entry;
    char in_path[512], out_path[512];

    if (!dir) {
        perror("[ERREUR] Ouverture du dossier Projet/");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && extension_chiffree(entry->d_name)) {
            snprintf(in_path, sizeof(in_path), "%s/%s", dir_path, entry->d_name);

            // Enlever le .enc pour retrouver le nom original
            strncpy(out_path, in_path, sizeof(out_path));
            out_path[strlen(out_path) - 4] = '\0';

            dechiffrer_fichier(in_path, out_path, key, iv);
        }
    }

    closedir(dir);
}

int main() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    printf("Veuillez écrire une justification (20 caractères min) :\n> ");
    char message[1024];
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = '\0';

    if (strlen(message) < 20) {
        fprintf(stderr, "[ERREUR] Message trop court. Déchiffrement refusé.\n");
        return 1;
    }

    // Création de la socket client
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[ERREUR] Création socket");
        return 1;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT)
    };
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    printf("[INFO] Connexion au serveur %s:%d...\n", SERVER_IP, PORT);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERREUR] Connexion échouée");
        return 1;
    }

    // Envoi du message
    send(sock, message, strlen(message), 0);
    printf("[INFO] Justification envoyée.\n");

    // Réception clé + IV
    unsigned char key[32], iv[16];
    ssize_t k = recv(sock, key, sizeof(key), MSG_WAITALL);
    ssize_t i = recv(sock, iv, sizeof(iv), MSG_WAITALL);
    if (k != 32 || i != 16) {
        fprintf(stderr, "[ERREUR] Clé ou IV mal reçus. Réception interrompue.\n");
        return 1;
    }

    printf("[OK] Clé et IV reçus. Déchiffrement en cours...\n");

    parcourir_et_dechiffrer(PROJET_DIR, key, iv);

    close(sock);
    EVP_cleanup();
    ERR_free_strings();

    printf("[FIN] Tous les fichiers ont été traités.\n");
    return 0;
}

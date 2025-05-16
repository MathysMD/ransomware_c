#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <arpa/inet.h>

#define PORT 4242
#define SERVER "127.0.0.1"
#define PROJET_DIR "Projet"
#define BUFFER_SIZE 4096

// Vérifie si le fichier se termine par ".enc"
int est_fichier_chiffre(const char *filename) {
    return strstr(filename, ".enc") != NULL;
}

// Supprime l'extension ".enc" pour retrouver le nom original
void retirer_extension(const char *src, char *dest) {
    strcpy(dest, src);
    char *p = strstr(dest, ".enc");
    if (p) *p = '\0';
}

// Déchiffre un fichier avec AES-256-CBC
void dechiffrer_fichier(const char *input, const char *output, unsigned char *key, unsigned char *iv) {
    FILE *in = fopen(input, "rb");
    FILE *out = fopen(output, "wb");
    if (!in || !out) { perror("[ERREUR] Ouverture fichier"); return; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, out);
    }

    EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    remove(input); // Supprime le fichier chiffré
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char message[1024], buffer[1024];
    unsigned char key[32], iv[16];

    printf("Veuillez écrire une justification (20 caractères min) :\n> ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = 0; // Supprime le retour à la ligne

    // Connexion au serveur
    sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER);

    connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    send(sock, message, strlen(message), 0);

    // Si la justification est suffisante, on reçoit clé + IV
    int k = recv(sock, key, 32, 0);
    int v = recv(sock, iv, 16, 0);

    if (k == 32 && v == 16) {
        printf("[OK] Clé et IV reçus. Déchiffrement en cours...\n");

        DIR *dir = opendir(PROJET_DIR);
        struct dirent *entry;
        char input[256], output[256];

        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG && est_fichier_chiffre(entry->d_name)) {
                snprintf(input, sizeof(input), "%s/%s", PROJET_DIR, entry->d_name);
                retirer_extension(input, output);
                printf("[INFO] Déchiffrement du fichier : %s\n", entry->d_name);
                dechiffrer_fichier(input, output, key, iv);
            }
        }

        closedir(dir);
        printf("[FIN] Tous les fichiers ont été traités.\n");

    } else {
        recv(sock, buffer, sizeof(buffer), 0);
        printf("[ERREUR] %s\n", buffer);
    }

    close(sock);
    return 0;
}

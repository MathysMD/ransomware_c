#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <openssl/rand.h>

#define CHEMIN_PROJET "TP/Projet"
#define DELAI_SECONDES 30  // pour test
#define CLE_FICHIER "cle.key"
#define IV_FICHIER "cle.iv"

int dossier_existe(const char *chemin) {
    struct stat st;
    return stat(chemin, &st) == 0 && S_ISDIR(st.st_mode);
}

void generer_cle_et_iv(unsigned char *key, unsigned char *iv) {
    RAND_bytes(key, 32); // 256 bits
    RAND_bytes(iv, 16);  // 128 bits

    FILE *fk = fopen(CLE_FICHIER, "wb");
    FILE *fi = fopen(IV_FICHIER, "wb");

    if (fk && fi) {
        fwrite(key, 1, 32, fk);
        fwrite(iv, 1, 16, fi);
        fclose(fk);
        fclose(fi);
        printf("Clé AES-256 et IV générés et sauvegardés.\n");
    } else {
        perror("Erreur lors de la sauvegarde de la clé ou de l'IV");
        exit(1);
    }
}

int main() {
    printf("Surveillance du dossier '%s'...\n", CHEMIN_PROJET);

    while (!dossier_existe(CHEMIN_PROJET)) {
        sleep(5);
    }

    printf("Dossier détecté : %s\n", CHEMIN_PROJET);

    time_t debut = time(NULL);
    printf("Timer lancé pour %d secondes à %s", DELAI_SECONDES, ctime(&debut));

    while (difftime(time(NULL), debut) < DELAI_SECONDES) {
        sleep(1);
    }

    printf("Temps écoulé. Génération de la clé de chiffrement...\n");

    unsigned char key[32];
    unsigned char iv[16];
    generer_cle_et_iv(key, iv);

    return 0;
}

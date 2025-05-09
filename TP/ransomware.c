#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>

#define CHEMIN_PROJET "TP/Projet"
#define DELAI_SECONDES 30  // À remplacer par 3600 pour 1h

// Vérifie si un dossier existe
int dossier_existe(const char *chemin) {
    struct stat st;
    return stat(chemin, &st) == 0 && S_ISDIR(st.st_mode);
}

int main() {
    printf("Surveillance du dossier '%s'...\n", CHEMIN_PROJET);
    fflush(stdout);

    // Attente de la création du dossier Projet/
    while (!dossier_existe(CHEMIN_PROJET)) {
        sleep(5);
    }

    printf("Dossier détecté : %s\n", CHEMIN_PROJET);

    // Timestamp de début
    time_t debut = time(NULL);
    char *date_debut = ctime(&debut);
    printf("Timer lancé pour %d secondes à %s", DELAI_SECONDES, date_debut);
    fflush(stdout);

    // Attente pendant DELAI_SECONDES
    while (difftime(time(NULL), debut) < DELAI_SECONDES) {
        sleep(1);
    }

    printf("Temps écoulé. Début du chiffrement...\n");
    return 0;
}

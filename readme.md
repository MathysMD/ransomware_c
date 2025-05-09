---

## Le Fonctionnement : 

### 1. L’agent `ransomware`

1. **Surveillance**
   Le programme reste actif en arrière-plan et regarde toutes les 5 secondes si un dossier nommé **Projet/** a été créé.
2. **Compte à rebours**
   Dès que “Projet/” apparaît, un minuteur démarre (30 secondes pour les tests, 1 heure en version finale).
3. **Préparation du chiffrement**
   Quand le temps est écoulé, l’agent :

   * Produit **une clé secrète** et **un vecteur d’initialisation** (IV) grâce à OpenSSL.
   * Sauvegarde ces deux données dans les fichiers **cle.key** et **cle.iv**.
4. **Chiffrement des fichiers**
   Pour chaque document **.txt**, **.md**, **.c** ou **.h** dans Projet/ :

   * Le fichier est lu en mode binaire.
   * Son contenu est transformé (chiffré) bloc par bloc.
   * Le fichier chiffré est écrit avec l’extension **.enc**, puis l’original est supprimé.
5. **Message de rançon**
   L’agent crée un fichier **Projet/RANÇON.txt** qui explique les consignes pour récupérer la clé.
6. **Démarrage automatique du serveur**
   Enfin, l’agent lance en tâche de fond le programme **serveur\_pardon**, lequel attend la connexion du client.

### 2. Le serveur `serveur_pardon`

1. **Écoute**
   Il ouvre un canal réseau local sur le port **4242** et patiente jusqu’à ce qu’un client se connecte.
2. **Réception des excuses**
   Quand quelqu’un se connecte, il lit la justification envoyée.
3. **Validation**

   * Si le texte contient au moins 20 caractères, il considère que les excuses sont sincères.
   * Il envoie alors au client la **clé** et l’**IV** pour pouvoir déchiffrer les fichiers.
   * Sinon, il indique que la justification est insuffisante et interrompt la connexion.

### 3. Le client `client_decrypt`

1. **Connexion**
   Il se connecte à l’adresse `127.0.0.1` sur le port **4242**.
2. **Envoi des excuses**
   Il demande à l’utilisateur de taper son message d’excuse et l’envoie au serveur.
3. **Réception de la clé**
   Si le serveur accepte, le client reçoit la clé (32 octets) et l’IV (16 octets).
4. **Restitution des fichiers**
   Le programme parcourt alors `Projet/`, ouvre chaque fichier **.enc**, le déchiffre avec la clé reçue, recrée le fichier original (sans `.enc`) et supprime la version chiffrée.

---

## Comment compiler

  Dans le dossier `TP/` et exécuter :

```bash
gcc ransomware.c       -o ransomware     -lssl -lcrypto
gcc serveur_pardon.c   -o serveur_pardon
gcc client_decrypt.c   -o client_decrypt -lssl -lcrypto
```

---

## Étapes d’utilisation

1. **Lancer l’agent**

   ```bash
   ./ransomware
   ```

   L’agent affiche un message et attend la création de `Projet/`.

2. **Préparer le dossier Projet/**
   Dans un autre terminal :

   ```bash
   mkdir Projet
   echo "Mon rapport" > Projet/rapport.txt
   echo "int main(){}" > Projet/main.c
   echo "# Notes" > Projet/notes.md
   ```

3. **Attendre le chiffrement**
   Après 1 heure, l’agent chiffre les fichiers et lance automatiquement le serveur.

4. **Déchiffrer**
   Toujours dans `TP/`, exécute :

   ```bash
   ./client_decrypt
   ```

   * Tape un message d’excuse (au moins 20 caractères).
   * Les fichiers restaurés se retrouvent dans `Projet/`.

---

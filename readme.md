
## Le Fonctionnement : 

### 1. L’agent `ransomware`

1. **Surveillance**

   * Le programme est lancé manuellement.
   * Il reste en veille active et **surveille toutes les 5 secondes** l’apparition d’un dossier nommé `Projet/`.

2. **Compte à rebours**

   * Dès que le dossier `Projet/` est détecté, un **minuteur de 30 secondes** démarre *(1 heure en version finale)*.

3. **Préparation du chiffrement**

   * Une **clé AES-256** (32 octets) et un **vecteur d'initialisation (IV)** (16 octets) sont générés de manière aléatoire à l’aide d’OpenSSL.
   * Ces données sont **sauvegardées localement** dans `cle.key` et `cle.iv`.

4. **Chiffrement des fichiers**

   * Chaque fichier de type `.txt`, `.md`, `.c` ou `.h` dans `Projet/` est :

     * **Lu en binaire**
     * **Chiffré bloc par bloc** avec AES-256-CBC
     * **Enregistré sous forme chiffrée** avec l’extension `.enc`
     * **L’original est supprimé**

5. **Création du message de rançon**

   * Un fichier `Projet/RANÇON.txt` est généré avec des instructions pour récupérer les fichiers.

6. **Lancement automatique du serveur**

   * Le programme `serveur_pardon` est lancé **automatiquement en tâche de fond**.

7. **Transmission sécurisée de la clé**

   * Une fois le serveur démarré, `ransomware` **se connecte en TCP au serveur** et lui transmet la **clé AES** et **l’IV**.
   * Ces fichiers sont ensuite **supprimés localement** pour simuler un vrai comportement de ransomware

### 2. Le serveur `serveur_pardon`

1. **Écoute**

   * Le serveur ouvre une **socket TCP locale** sur le port `4242` et attend une connexion entrante.

2. **Réception de la justification**

   * Lorsqu’un client se connecte, il lit un **message d’excuse** envoyé par l’utilisateur.

3. **Validation**

   * Si le message fait **au moins 20 caractères**, il considère que l’excuse est valide.
   * Le serveur envoie alors la **clé AES** et l’**IV** au client.
   * Sinon, il renvoie un message d’échec.


### 3. Le client `client_decrypt`

1. **Connexion au serveur**

   * Se connecte en TCP à `127.0.0.1:4242`.

2. **Envoi de l'excuse**

   * Demande à l’utilisateur de **saisir une justification écrite**.

3. **Réception de la clé et de l’IV**

   * Si la justification est acceptée, le client reçoit la **clé de déchiffrement** et le **vecteur IV**.

4. **Déchiffrement des fichiers**

   * Le client parcourt tous les fichiers `.enc` dans `Projet/`.
   * Chaque fichier est :

     * **Ouvert en binaire**
     * **Déchiffré bloc par bloc** en utilisant OpenSSL
     * **Restauré sous son nom d’origine** (sans `.enc`)
     * **Le fichier chiffré est supprimé**

## Comment compiler

Se placer dans le dossier `TP/` et exécuter :

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

   > Le programme surveille l’apparition du dossier `Projet/`.

2. **Créer le dossier Projet/**

   Dans un autre terminal :

   ```bash
   mkdir Projet
   echo "Mon rapport" > Projet/rapport.txt
   echo "int main(){}" > Projet/main.c
   echo "# Notes" > Projet/notes.md
   ```

3. **Attendre le chiffrement**

   * Après 30 secondes (ou 1h), les fichiers sont chiffrés.
   * Le serveur est lancé automatiquement.
   * La clé AES et l’IV sont envoyés au serveur puis **effacés localement**.

4. **Déchiffrer les fichiers**

   Toujours depuis le dossier `TP/` :

   ```bash
   ./client_decrypt
   ```

   * Saisir une **excuse d’au moins 20 caractères**.
   * Si acceptée, les fichiers originaux seront **automatiquement restaurés** dans `Projet/`.

��    g      T  �   �      �     �  +   �  4   �     '	      >	  +   _	  -   �	  &   �	  "   �	     
     
  #   6
     Z
  2   k
     �
  3   �
  "   �
     �
       7        U  C   g  (   �  +   �  >         ?      V  #   w  /   �  $   �  -   �  0     5   O  9   �  3   �  &   �  9        T  &   \  *   �     �  �  �     i  3   x      �     �  !   �          #     C     c      |     �  "   �     �  &   �       3   ,     `     ~  (   �     �     �  :   �      ,  ;   M  "   �  ,   �     �     �     
         $   A     f  (   �     �     �     �  8     %   ;  !   a  !   �     �  H   �  7   �     6     H  %   h     �  -   �     �  G   �  9   <  ?   v  1   �  +   �  2        G  <   ]  ;   �     �     �  �        �  ,     F   >     �  +   �  1   �  ;   �  &   6  %   ]  +   �  !   �  5   �       A        X  T   d  '   �     �     �  ;   	     E  N   Y  )   �  )   �  B   �     ?  1   V  2   �  >   �  )   �  9   $  @   ^  B   �  E   �  3   (   /   \   B   �      �   8   �   Y   !     j!  �  �!     X#  <   p#  &   �#  %   �#  /   �#  %   *$  )   P$  *   z$  1   �$  ,   �$     %  1   %     N%  *   i%  &   �%  D   �%  &    &  '   '&  >   O&  !   �&     �&  c   �&  $   )'  E   N'  %   �'  =   �'     �'  &   (  !   5(  &   W(  2   ~(     �(  ,   �(     �(  ,   )     C)  K   ^)  .   �)  ,   �)  &   *     -*  Y   @*  =   �*     �*  )   �*  /   +     L+  ?   l+  (   �+  b   �+  E   8,  L   ~,  4   �,  /    -  D   0-     u-  I   �-  C   �-     .  #   :.     K      Y   1       =      C      Q   "   #                                J   F      4   b       @           <      f                  :       W   H   _             7   X   %   	   2   3   R   D   !   ;      V   E   O   A   -   a       +   e   $      /       U       T       *   [      c   &       )      g   ]   B   Z      0          N   G      ^   I      \       
             M   6   d   ?   5                  9   S   P          `      >   .      L   (                      8          '   ,                       '{0}' does not exist '{0}' is not a regular file nor a directory Allow the kernel to cache data from this file system Available subcommands: Define the editor command to use Defines the key slot to erase in range 1..7 Defines the path for akt global configuration Defines the path for the keystore file Do not output the trailing newline Enable debug dump execution Enable debug execution Enable debug output of fuse library Enter password:  Erase and fill with zeros instead of random values Extract  Force erase of password used to unlock the keystore Force the creation of the keystore Invalid command New password:  Number of threads for the encryption/decryption process Print the version Read the environment variable that contains the password (not safe) Read the file that contains the password Read the file that contains the wallet keys Read the password from the pipe with the given file descriptor Remove the otpauth URI Run as foreground (no daemonize) Run the command to get the password Run the ssh-askpass command to get the password Set the range for the PBKDF2 counter Split the data blocks in COUNT separate files Store the result in the output file or directory The directory which contains the keystore data blocks The password is passed within the command line (not safe) The password is passed within the socket connection The password was successfully removed. Type '{0} help {command}' for help on a specific command. Usage:  Use gpg to protect the keystore access Use the standard input to read the content Verbose execution mode [-V] [-v] [-vv] [-vvv] [-c path] [-t count] [-z] <command> [<args>]
where:
  -V           Print the tool version
  -v           Verbose execution mode
  -vv          Debug execution mode
  -vvv         Dump execution mode
  -c path      Defines the path for akt global configuration
  -t count     Number of threads for the encryption/decryption process
  -z           Erase and fill with zeros instead of random values add a password akt - tool to store and protect your sensitive data algorithm '{0}' is not supported cannot access file: {0} cannot create file for the editor cannot execute editor '{0}' cannot open keystore '{0}': {1} cannot read the editor's output cannot run in background cannot set the permission of {0} change the password counters must be positive integers create the keystore edit the value with an external editor editor exited with status{0} generate a one time password or manage OATH secrets get a value from the keystore get or set global options insert or update a value in the keystore invalid counter range: {0} invalid digits '{0}' invalid key slot number: it must be a number in range 1..7 invalid keystore file '{0}': {1} invalid or truncated keystore file '{0}': size is incorrect invalid otpauth URI: missing '{0}' invalid password to unlock the keystore file invalid period '{0}' list values of the keystore missing GPG user name missing command name to execute. missing file or directory to extract missing name and value to set missing name to store the standard input missing option parameter missing the keystore file name missing value name to remove mount the keystore on the filesystem for a direct access no content for an item of type wallet no otpauth matching account '{0}' override existing otpauth entry ? print some help read the standard input and insert or update the content in the keystore refusing to erase the key slot used by current password remove a password remove values from the keystore report information about the keystore some internal error occurred split counter is invalid or out of range: {0} the file is not a keystore the keystore file is corrupted: invalid data block headers or signature the keystore file is corrupted: invalid meta data content the keystore file is corrupted: invalid or missing storage file the keystore file is corrupted: invalid signature the min counter is greater than max counter there is no available key slot to add the password unknown command '{0}' use the --force option if you really want to erase this slot valid format are 'MAX_COUNTER' or 'MIN_COUNTER:MAX_COUNTER' value '{0}' not found value is out of range Project-Id-Version: akt 1.3.0
Report-Msgid-Bugs-To: Stephane.Carrez@gmail.com
PO-Revision-Date: 2023-03-05\nLast-Translator: Carrez
Language-Team: 
Language: fr
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
 '{0}' n'existe pas '{0}' n'est pas un fichier ni un répertoire Permettre au noyau de cacher les données pour ce système de fichiers Commandes disponibles: Définir la commande d'éditeur à utiliser Définit l'emplacement de la clé à effacer 1..7 Définit le chemin du fichier global de configuration d'akt Définit le chemin du fichier de clés Ne pas afficher le retour à la ligne Activer l'exécution du débogage avec dump Activer l'exécution du débogage Activer l'execution du débogage de la librairie fuse Mot de passe:  Effacer et remplir avec des zéros au lieu de valeurs aléatoires Extraction  Forcer l'effacement du mot de passe utilisé pour déverrouiller le magasin de clés Forcer la création du magasin de clés command invalide Nouveau mot de passe:  Nombre de threads pour le processus de cryptage/décryptage Afficher la version Lire la variable d’'environnement contenant le mot de passe (non sécurisé) Lire un fichier contenant le mot de passe Lire un fichier contenant le mot de passe Lire le mot de passe du tube avec le descripteur de fichier donné Supprime l'URI otpauth Lancer la commande en premier plan (no daemonize) Exécuter la commande pour obtenir le mot de passe Exécuter la commande ssh-askpass pour obtenir le mot de passe Définir la plage pour le compteur PBKDF2 Scinder les blocs de données en COUNT fichiers séparés Stocker le résultat dans le fichier ou le répertoire de sortie Le répertoire contenant les blocs de données du magasin de clés Le mot de passe est passé dans la ligne de commande (non sécurisé) Le mot de passe est passé dans la connexion socket Le mot de passe a été supprimé avec succès. Tapez '{0} help {command}' pour l'aide d'une commande spécifique. Usage:  Utiliser gpg pour protéger l'accès au magasin de clés Lire l'entrée standard et insérer ou mettre à jour le contenu dans le magasin de clés Mode d'exécution détaillé [-V] [-v] [-vv] [-vvv] [-c path] [-t count] [-z] <command> [<args>]
où:
  -V           Afficher la version de l'outil
  -v           Mode d'execution verbeux
  -vv          Mode d'execution debug
  -vvv         Mode d'execution dump
  -c path      Définit le chemin du fichier de configuration global d'akt
  -t count     Nombre de threads pour le processus de cryptage/décryptage
  -z           Effacer et remplir avec des zéros au lieu de valeurs aléatoires ajouter un mot de passe akt - outil pour stocker et protéger vos données sensibles l'algorithme '{0}' n'est pas supporté impossible d'accéder au fichier: {0} impossible de créer un fichier pour l'éditeur impossible de lancer l'éditeur '{0}' impossible d'ouvrir le fichier '{0}': {1} impossible de lire la sortie de l'éditeur impossible de lancer l'execution en tache de fond impossible de définir l'autorisation de {0} changer le mot de passe les compteurs doivent être des entiers positifs. créer le magasin de clés éditer la valeur avec un éditeur externe L'éditeur a quitté avec le statut{0} générer un mot de passe à usage unique ou gérer les secrets OATH obtenir une valeur du magasin de clés obtenir ou configurer une option global insérer ou mettre à jour une valeur dans le magasin de clés plage de compteur non valide: {0} digits invalid '{0}' numéro de l'emplacement de clé non valide: il doit s'agir d'un numéro compris dans la plage 1..7 fichier de clés invalide '{0}': {1} fichier de clés invalide ou tronqué '{0}': la taille est incorrecte URI otpauth invalide: il manque '{0}' mot de passe invalide pour déverrouiller le fichier de clés period invalide '{0}' lister les valeurs du magasin de clés nom de l'identifiant GPG manquant nom de commande manquant à exécuter. nom du fichier ou répertoire à extraire manquant manque le nom et la valeur manque le nom pour sauver l'entrée standard paramètre d'option manquant manque le nom de fichier du magasin de clés manque le nom à supprimer monter le magasin de clés sur le système de fichier pour un accès direct pas de contenu pour une entrée de type wallet pas de otpauth correspondant au compte '{0}' écraser l'entrée otpauth existante ? afficher de l'aide lire l'entrée standard et insérer ou mettre à jour le contenu dans le magasin de clés refus d'éffacer la clé utilisée par le mot de passe actuel supprimer un mot de passe supprimer les valeurs du magasin de clés donner des informations sur le magasin de clés une erreur interne est survenue le compteur de fractionnement est invalide ou hors limites: {0} le fichier n'est pas un magasin de clés le fichier de clés est corrompu: en-têtes de blocs de données non valides ou signature invalide le fichier de clés est corrompu: contenu de métadonnées non valide le fichier de clés est corrompu: fichier de stockage non valide ou manquant le fichier de clés est corrompu: signature invalide le compteur mini est supérieur au compteur max il n'y a pas de slot de clé disponible pour ajouter le mot de passe command inconnue '{0}' utilisez l'option --force si vous voulez vraiment effacer cet emplacement les formats valides sont 'MAX_COUNTER' ou 'MIN_COUNTER:MAX_COUNTER' la valeur '{0}' est introuvable la valeur est en dehors des limites 
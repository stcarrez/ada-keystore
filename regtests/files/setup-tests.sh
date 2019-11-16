#!/bin/sh
rm -rf regtests/files/gnupg
ROOT=`pwd`/regtests/files/gnupg
USERS="user1 user2 user3"
for USER in $USERS; do
  mkdir -p regtests/files/gnupg/$USER
  chmod 700 regtests/files/gnupg/$USER
  echo "Creating GPG user $USER"
  echo "-----------------------"
  gpg2 --homedir=$ROOT/$USER --quiet \
       --batch --gen-key regtests/files/$USER-key-script.gpg
  gpg2 --homedir=$ROOT/$USER --quiet \
       --armor --export akt-$USER@ada-unit-test.org > $ROOT/$USER.asc
  gpg2 --homedir=$ROOT/$USER --quiet \
       --export-ownertrust >> $ROOT/ownertrust.asc

  # Generate an AKT configuration file for each user
  cat <<EOF > $ROOT/$USER-akt.properties
gpg-encrypt=gpg2 --homedir=$ROOT/$USER --encrypt --batch --yes --quiet -r \$USER
gpg-decrypt=gpg2 --homedir=$ROOT/$USER --decrypt --batch --yes --quiet
gpg-list-keys=gpg2 --homedir=$ROOT/$USER --list-secret-keys --with-colons --with-fingerprint
EOF
done

# Import GPG public keys for user1 so that he knows user2 and user3.
# user2 and user3 don't know each other.
gpg2 --homedir=`pwd`/regtests/files/gnupg/user1 --quiet \
     --import regtests/files/gnupg/user2.asc
gpg2 --homedir=`pwd`/regtests/files/gnupg/user1 --quiet \
     --import regtests/files/gnupg/user3.asc
gpg2 --homedir=`pwd`/regtests/files/gnupg/user1 --quiet \
     --import-ownertrust regtests/files/gnupg/ownertrust.asc

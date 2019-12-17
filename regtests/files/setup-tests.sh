#!/bin/sh
rm -rf regtests/files/gnupg
GPG=`which gpg2 2>/dev/null`
if test T$GPG = T; then
  GPG=gpg
fi
V=`$GPG --version`
echo "Using $V"
ROOT=`pwd`/regtests/files/gnupg
USERS="user1 user2 user3"
for USER in $USERS; do
  mkdir -p regtests/files/gnupg/$USER
  chmod 700 regtests/files/gnupg/$USER
  echo "Creating GPG user $USER"
  echo "-----------------------"
  $GPG --homedir=$ROOT/$USER --quiet \
       --batch --gen-key regtests/files/$USER-key-script.gpg
  $GPG --homedir=$ROOT/$USER --quiet \
       --armor --export akt-$USER@ada-unit-test.org > $ROOT/$USER.asc
  $GPG --homedir=$ROOT/$USER --quiet \
       --export-ownertrust >> $ROOT/ownertrust.asc

  # Generate an AKT configuration file for each user
  cat <<EOF > $ROOT/$USER-akt.properties
gpg-encrypt=$GPG --homedir=$ROOT/$USER --encrypt --batch --yes --quiet -r \$USER
gpg-decrypt=$GPG --homedir=$ROOT/$USER --decrypt --batch --yes --quiet
gpg-list-keys=$GPG --homedir=$ROOT/$USER --list-secret-keys --with-colons --with-fingerprint
EOF
done

# Import GPG public keys for user1 so that he knows user2 and user3.
# user2 and user3 don't know each other.
$GPG --homedir=`pwd`/regtests/files/gnupg/user1 --quiet \
     --import regtests/files/gnupg/user2.asc
$GPG --homedir=`pwd`/regtests/files/gnupg/user1 --quiet \
     --import regtests/files/gnupg/user3.asc
$GPG --homedir=`pwd`/regtests/files/gnupg/user1 --quiet \
     --import-ownertrust regtests/files/gnupg/ownertrust.asc


#!/bin/sh
NAME=keystore.cov
lcov --quiet --base-directory . --directory . \
   --no-external \
   --exclude '*/b__*.adb' \
   --exclude '*/regtests*' \
   --exclude '*/ada-util/*' \
   -c -o $NAME
rm -rf cover
genhtml --quiet -o ./cover -t "test coverage" --num-spaces 4 $NAME
 

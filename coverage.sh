#!/bin/sh
NAME=keystore.cov
lcov --quiet --base-directory . --directory . -c -o $NAME
lcov --quiet --remove $NAME "/usr*" -o $NAME
lcov --quiet --remove $NAME "/build*" -o $NAME
lcov --quiet --remove $NAME "/opt*" -o $NAME
lcov --quiet --remove $NAME "*/regtests*" -o $NAME
lcov --quiet --remove $NAME "*/adainclude*" -o $NAME
lcov --quiet --remove $NAME ada-keystore/b__keystore_harness.adb -o $NAME
lcov --quiet --remove $NAME ada-keystore/b__akt-main.adb -o $NAME
lcov --quiet --remove $NAME "*/b__keystore_harness.adb" -o $NAME
lcov --quiet --remove $NAME "*/b__akt-main.adb" -o $NAME
rm -rf cover
genhtml --quiet -o ./cover -t "test coverage" --num-spaces 4 $NAME
 

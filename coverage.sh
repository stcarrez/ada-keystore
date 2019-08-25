#!/bin/sh
#lcov --base-directory . --directory . -c -o keystore.cov
#bin/keystore_harness -xml keystore-aunit.xml
lcov --base-directory . --directory . -c -o keystore.cov
lcov --remove keystore.cov "/usr*" -o keystore.cov
lcov --remove keystore.cov "/build*" -o keystore.cov
lcov --remove keystore.cov "/opt*" -o keystore.cov
lcov --remove keystore.cov "regtests*" -o keystore.cov
lcov --remove keystore.cov "adainclude*" -o keystore.cov
lcov --remove keystore.cov ada-keystore/b__keystore_harness.adb -o keystore.cov
lcov --remove keystore.cov ada-keystore/b__akt-main.adb -o keystore.cov
lcov --remove keystore.cov "*/b__keystore_harness.adb" -o keystore.cov
lcov --remove keystore.cov "*/b__akt-main.adb" -o keystore.cov
rm -rf cover
genhtml -o ./cover -t "test coverage" --num-spaces 4 keystore.cov
 

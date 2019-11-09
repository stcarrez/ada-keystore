rm -f regtests/files/test-keystore.akt
# Use a low counter range to speed up the tests
bin/akt create -k regtests/files/test-keystore.akt -p mypassword --counter-range 1:1000 --force
bin/akt set -k regtests/files/test-keystore.akt -p mypassword list-1 'Licensed under the Apache License, Version 2.0 (the "License");'
bin/akt set -k regtests/files/test-keystore.akt -p mypassword list-2 'you may not use this file except in compliance with the License.'
bin/akt set -k regtests/files/test-keystore.akt -p mypassword list-3 'You may obtain a copy of the License at'
bin/akt set -k regtests/files/test-keystore.akt -p mypassword list-4 'http://www.apache.org/licenses/LICENSE-2.0'
bin/akt set -k regtests/files/test-keystore.akt -p mypassword -f LICENSE.txt
bin/akt list -k regtests/files/test-keystore.akt -p mypassword

rm -f regtests/files/test-keystore.akt
# Use a low counter range to speed up the tests
bin/akt -f regtests/files/test-keystore.akt -p mypassword create --counter-range 1:1000
bin/akt -f regtests/files/test-keystore.akt -p mypassword set list-1 'Licensed under the Apache License, Version 2.0 (the "License");'
bin/akt -f regtests/files/test-keystore.akt -p mypassword set list-2 'you may not use this file except in compliance with the License.'
bin/akt -f regtests/files/test-keystore.akt -p mypassword set list-3 'You may obtain a copy of the License at'
bin/akt -f regtests/files/test-keystore.akt -p mypassword set list-4 'http://www.apache.org/licenses/LICENSE-2.0'
bin/akt -f regtests/files/test-keystore.akt -p mypassword set LICENSE.txt -f LICENSE.txt
bin/akt -f regtests/files/test-keystore.akt -p mypassword list

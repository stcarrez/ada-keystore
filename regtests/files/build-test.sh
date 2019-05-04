rm -f regtests/files/test-keystore.ks
bin/akt -f regtests/files/test-keystore.ks -p mypassword create
bin/akt -f regtests/files/test-keystore.ks -p mypassword set list-1 'Licensed under the Apache License, Version 2.0 (the "License");'
bin/akt -f regtests/files/test-keystore.ks -p mypassword set list-2 'you may not use this file except in compliance with the License.'
bin/akt -f regtests/files/test-keystore.ks -p mypassword set list-3 'You may obtain a copy of the License at'
bin/akt -f regtests/files/test-keystore.ks -p mypassword set list-4 'http://www.apache.org/licenses/LICENSE-2.0'
bin/akt -f regtests/files/test-keystore.ks -p mypassword set LICENSE.txt -f LICENSE.txt
bin/akt -f regtests/files/test-keystore.ks -p mypassword list

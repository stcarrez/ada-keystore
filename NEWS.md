Version 1.4.1 - Sep 2024
  - Cleanup build environment to drop configure
  - Fix #21: list command limit 50
  - Fix #24: Cannot add a GPG user on a keystore having a password

Version 1.4.0  - Jul 2023
  - Feature #15: Authenticator with TOTP support
  - Fix #16: Support to build with -gnatW8
  - Fix #17: Test with corrupted data block sometimes dump the corrupted data
  - New genkey and otp commands

Version 1.3.4  - Feb 2023
  - Fix #14: Constraint_Error raised if the HOME environment variable is not defined
  - Fix fuse detection on FreeBSD
  - Fix building docker image

Version 1.3.3  - Aug 2022
  - Fix GPG support on MacOS

Version 1.3.2  - Jul 2021
  - Minor compilation warning fixes

Version 1.3.1  - Feb 2021
  - Improvement of message localization

Version 1.3.0  - Dec 2020
  - Added Write and Read direct data access
  - Finalize and fix the Fuse filesystem
  - Document the mount command
  - Fix deleting large data contents

Version 1.2.1  - Nov 2020
  - Add Alire template crate

Version 1.2.0  - May 2020
  - Added support for Fuse with a new mount command in akt (beta!)
  - Fix the implementation to iterate with Keystore.Properties

Version 1.1.0  - Feb 2020
  - Added Keystore.Properties support
  - Fixed erasing values stored in the keystore in some cases
  - Increased test coverage

Version 1.0.0  - Dec 2019
  - First version of AKT



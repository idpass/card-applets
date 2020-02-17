# ID PASS

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v1.4%20adopted-ff69b4.svg)](code-of-conduct.md)
![GitHub](https://img.shields.io/github/license/idpass/card-applets)
[![CircleCI](https://circleci.com/gh/idpass/card-applets.svg?style=svg)](https://circleci.com/gh/idpass/card-applets)

# General design
![ID PASS applets](https://github.com/idpass/card-applets/blob/master/idpass-diagram.jpg)

### How to build the project

The project is built using Gradle with the [Gradle Javacard 1.6.3](https://github.com/ph4r05/javacard-gradle-plugin).

To build and run unit test cases: 
- git clone --recurse-submodule ssh://git@github.com/idpass/card-applets
- git checkout pre-release
- git submodule update --init
- ./gradlew build

For the `signTransactionTest()` test case, you will need to run locally ganache blockchain simulator node either by `npm` or by `docker` then replace the value of 
the wallet key pair accordingly in `Main.java`. 


### General SW List

SW | DESCRIPTION
-- | -- 
0x9000 | No error
0x6982 | SCP Security Level is too low
0x6B00 | Incorrect parameters (P1,P2)
0x6700 | Wrong DATA length

### Packages
1. **[tools](https://github.com/idpass/card-tools-applet)** - package contains common classes, used in other ID PASS applets. **MUST** be uploaded first.
2. **[auth](https://github.com/idpass/card-auth-applet)** - package contains applet for Personas authentication
3. **[sam](https://github.com/idpass/card-sam-applet)** - package contains applet for encryption and decryption Personas data
3. **[datastorage](https://github.com/idpass/card-storage-applet)** - package contains applet for personas data storage
4. **[sign](https://github.com/idpass/card-sign-applet)** - package contains applet for digital signature

ID PASS applets support ExtendedLength APDUs.
Project contains **scripts** folder with JCShell scripts for demonstration and testing.

### Contributors

Contributions are welcome!

- Newlogic Impact Lab
- Maksim Samarskiy

# ID PASS

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v1.4%20adopted-ff69b4.svg)](code-of-conduct.md)
![GitHub](https://img.shields.io/github/license/idpass/card-applets)

# General design
![ID PASS applets](https://github.com/idpass/card-applets/blob/master/idpass-diagram.jpg)

### How to build the project

The project is built using Gradle with the [Fidesmo Javacard Gradle plugin](https://github.com/fidesmo/gradle-javacard).
You can set the JavaCard HOME not only through the environment but also creating a `gradle.properties` file with the
property `com.fidesmo.gradle.javacard.home` set to the correct absolute path. Here is an example `gradle.properties` content:

```
com.fidesmo.gradle.javacard.home=/absolute/path/to/card-applets/libs-sdks/jc304_kit/
```

However, the `_JAVA_OPTIONS` can only be set at an environment level. Please see `build.sh`

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

ID PASS applets support ExtendedLength APDUs.
Project contains **scripts** folder with JCShell scripts for demonstration and testing.

### Contributors

Contributions are welcome!

- Newlogic Impact Lab
- Maksim Samarskiy

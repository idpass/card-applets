# General design
![ID PASS applets](https://github.com/idpass/card-applets/blob/master/idpass-diagram.jpg)

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

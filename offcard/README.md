# GlobalPlatform Card Spec 2.1.1

### Applet privileges
- b8=1 indicates that the Application is a Security Domain.
- b7=1 indicates that the Security Domain has DAP Verification capability.
- b6=1 indicates that the Security Domain has Delegated Management privileges.
- b5=1 indicates that the Application has the privilege to lock the card.
- b4=1 indicates that the Application has the privilege to terminate the card.
- b3=1 indicates that the Application has the Default Selected privilege.
- b2=1 indicates that the Application has CVM management privileges.
- b1=1 indicates that the Security Domain has mandated DAP Verification capability.

### CLA
- 0x00 Command defined in ISO/IEC 7816
- 0x80 Proprietary command
- 0x84 Proprietary command with secure messaging

### Key Type
- 0x00 - 0x7F Reserved
- 0x80 DES - mode (EBC/CBC) implicitely known
- ...

### Miscelaneous (from specs)
- The `ISD` shall be the Default Selected Application
- An initial key shall be available within the `ISD`

### Miscelaneous (from observation)
- Once a key is added, the default factory `kvno` of `0xFF` with default key `40 .. 4F` is forever lost. The offcard must explicitely declare a keyset.
- One a key is added, it cannot be deleted. But only replaced with new key value
- In the JCOP terminal, `/send` != `send`. These are the insecure and secure variations of sending an apdu
- Once a data attempts to go out from an applet **insecurely**, it resets the applet's security level to 0x00. The JCOP terminal still thinks 0x83 though. 
- Always first load `tools.cap`  

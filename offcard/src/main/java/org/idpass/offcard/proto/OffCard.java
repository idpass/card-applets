package org.idpass.offcard.proto;

import java.io.ByteArrayOutputStream;

import java.io.IOException;
import java.security.SecureRandom;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.applet.DummyIssuerSecurityDomain;
import org.idpass.offcard.misc.Helper;
import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc._o;

import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.Util;
// import javacardx.crypto.Cipher; // @watch@

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class OffCard
{
    private static OffCard instance;

    private CardChannel channel;

    private static final byte[] _icv = CryptoAPI.NullBytes8.clone();

    private byte[] sENC;
    private byte[] sMAC;
    private byte[] sDEK;

    private String currentSelected;

    private Invariant Assert = new Invariant();

    private SCP02SecureChannel cardSecurityState;

    private SCP02SecureChannel offCardSecurityState;

    private Mode mode;

    public Mode getMode()
    {
        return mode;
    }

    private OffCard(CardChannel channel)
    {
        String s = channel.getClass().getCanonicalName();
        if (s.equals(
                "com.licel.jcardsim.smartcardio.CardSimulator.CardChannelImpl")) {
            mode = Mode.SIM;
        } else {
            mode = Mode.PHY;
        }
        this.channel = channel;

        // Keys inside off-card
        SCP02Keys offcardKeys[] = new SCP02Keys[] {
            new SCP02Keys("404142434445464748494a4b4c4d4e4F", // 1
                          "404142434445464748494a4b4c4d4e4F",
                          "404142434445464748494a4b4c4d4e4F"),
            new SCP02Keys("DEC0DE0102030405060708090A0B0C0D", // 2
                          "DEC0DE0102030405060708090A0B0C0D",
                          "DEC0DE0102030405060708090A0B0C0D"),
            new SCP02Keys(
                "CAFEBABE0102030405060708090A0B0C", // 3 
                "CAFEBABE0102030405060708090A0B0C",
                "CAFEBABE0102030405060708090A0B0C"),
            new SCP02Keys("C0FFEE0102030405060708090A0B0C0D", // 4
                          "C0FFEE0102030405060708090A0B0C0D",
                          "C0FFEE0102030405060708090A0B0C0D"),
        };

        // This is the off-card side of the secure channel
        offCardSecurityState = new SCP02SecureChannel(offcardKeys);
        finalizeReset();
    }

    // This is the correct abstraction!
    public org.globalplatform.SecureChannel getSecureChannelInstance()
    {
        if (cardSecurityState == null) {
            // This is the card side of the SecureChannel.
            // All applets in the card shares this single instance.
            // The card side and the off-card side of the secure channel
            // follows a lock-step matching state. When
            // one side diverges, the other side will not know. It will
            // only find it out on the next transmission fail and then
            // resets the security level.
            //
            // By putting it here close to the channel.transmit() I/O
            // it allows me to control securityLevel values when
            // targeting physical card, thus allowing the mirror classes
            // to operate without jcardsim.
            // A unified flow between simulator and physical.
            //
            // Take note that during simulation, it is due to jcardsim's
            // faithful compliance to invoke the SecureChannel callback that
            // tracks the securityLevel.

            // Keys inside the card
            SCP02Keys cardKeys[] = new SCP02Keys[] {
                new SCP02Keys("404142434445464748494a4b4c4d4e4F", // 1
                              "404142434445464748494a4b4c4d4e4F",
                              "404142434445464748494a4b4c4d4e4F"),
                new SCP02Keys("DEC0DE0102030405060708090A0B0C0D", // 2
                              "DEC0DE0102030405060708090A0B0C0D",
                              "DEC0DE0102030405060708090A0B0C0D"),
                new SCP02Keys(
                    "CAFEBABE0102030405060708090A0B0C", // 3 
                                                        
                    "CAFEBABE0102030405060708090A0B0C",
                    "CAFEBABE0102030405060708090A0B0C"),
                new SCP02Keys("C0FFEE0102030405060708090A0B0C0D", // 4
                              "C0FFEE0102030405060708090A0B0C0D",
                              "C0FFEE0102030405060708090A0B0C0D"),
            };

            cardSecurityState = new SCP02SecureChannel(cardKeys);
        }

        return cardSecurityState;
    }

    public static void reInitialize()
    {
        /*if (instance != null) {
            SCP02SecureChannel.count = 0;
            instance.finalizeReset();
        }*/
        instance = null;
        SCP02SecureChannel.count = 0;
    }

    public static OffCard getInstance()
    {
        return instance;
    }

    public static OffCard createInstance(CardChannel chan)
    {
        if (instance == null) {
            instance = new OffCard(chan);
        }

        return instance;
    }

    public byte[] select_cm()
    {
        byte[] retval = select(DummyIssuerSecurityDomain.class);
        return retval;
    }

    public void ATR()
    {
        if (mode == Mode.SIM) {
            // simulator.reset(); // DO NOT CALL THIS method!
            // This resets security level of previously selected applet
            select(DummyIssuerSecurityDomain.class); // invoke security reset
        } else if (mode == Mode.PHY) {
            // card.getATR(); // ?
            select(DummyIssuerSecurityDomain.class); // invoke security reset
        }
    }

    public void install(Class<? extends javacard.framework.Applet> cls)
    {
        // Get applet parameters
        IdpassConfig cfg = cls.getAnnotation(IdpassConfig.class);
        String strId = cfg.appletInstanceAID();
        byte[] installParams = cfg.installParams();
        byte[] privileges = cfg.privileges();

        byte[] bArray = {};
        byte[] id_bytes = Hex.decode(strId);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(id_bytes.length);
            bos.write(id_bytes);
            bos.write(privileges.length);
            if (privileges.length > 0) {
                bos.write(privileges);
            }
            bos.write(installParams.length);
            if (installParams.length > 0) {
                bos.write(installParams);
            }
            bArray = bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }

        AID aid = AIDUtil.create(id_bytes);

        switch (mode) {
        case PHY: {
            Method initMethod;

            try {
                initMethod = cls.getMethod(
                    "install",
                    new Class[] {byte[].class, short.class, byte.class});
            } catch (NoSuchMethodException e) {
                throw new IllegalArgumentException(
                    "Class does not provide install method");
            }

            try {
                initMethod.invoke(null, bArray, (short)0, (byte)bArray.length);
            } catch (InvocationTargetException e) {
                try {
                    ISOException isoException = (ISOException)e.getCause();
                    throw isoException;
                } catch (ClassCastException cce) {
                    throw new SystemException(SystemException.ILLEGAL_AID);
                }
            } catch (Exception e) {
                throw new SystemException(SystemException.ILLEGAL_AID);
            }
        } break;

        case SIM:
            Helper.simulator.installApplet(
                aid, cls, bArray, (short)0, (byte)bArray.length);
            break;
        }
    }

    public byte[] select(Class<? extends javacard.framework.Applet> cls)
    {
        this.offCardSecurityState.resetSecurity();

        byte[] result = new byte[] {(byte)0x6A, (byte)0xA2};

        IdpassConfig cfg = cls.getAnnotation(IdpassConfig.class);

        String strId = cfg.appletInstanceAID();
        byte[] id_bytes = Hex.decode(strId);
        currentSelected = cls.getCanonicalName();

        if (mode == Mode.SIM) {
            result = Helper.simulator.selectAppletWithResult(
                AIDUtil.create(id_bytes)); // @diff1_@
        } else if (mode == Mode.PHY) {
            result = selectAppletWithResult(id_bytes); // @diff1@
        }

        ResponseAPDU response = new ResponseAPDU(result);
        Assert.assertEquals(0x9000, response.getSW());

        // byte[] sw = new byte[2];
        // System.arraycopy(result, result.length - 2, sw, 0, sw.length);
        // String s = String.format("SELECT %s ERROR", currentSelected);
        // Assert.assertEquals(sw, Helper.SW9000, s);

        return result;
    }

    public ResponseAPDU Transmit(CommandAPDU apdu)
    {
        byte sL = offCardSecurityState.getSecurityLevel();

        ResponseAPDU response = new ResponseAPDU(new byte[] {
            (byte)0x67,
            (byte)0x01,
        });

        byte[] tx = apdu.getBytes();
        byte[] rx = {};

        try {
            byte cla = (byte)apdu.getCLA();
            byte ins = (byte)apdu.getINS();
            byte p1 = (byte)apdu.getP1();
            byte p2 = (byte)apdu.getP2();
            byte[] data = apdu.getData();
            byte[] newData = null;

            if ((sL & Helper.GP.C_MAC) != 0) {
                System.out.println("Transmit C_MAC");
            }

            if ((sL & Helper.GP.C_DECRYPTION) != 0) {
                System.out.println("Transmit C_DECRYPTION");
            }

            newData = data.clone();

            CommandAPDU command = new CommandAPDU(cla, ins, p1, p2, newData);

            response = channel.transmit(command);
            rx = response.getBytes();

        } catch (CardException e) {
            rx = response.getBytes();
        }
        System.out.println(
            "\n----------------------------------------------- OffCard::Transmit --------------------------------------------------------------");
        System.out.println(currentSelected + ":");
        System.out.println(String.format("=> %s", Helper.print(tx)));
        System.out.println(String.format("<= %s", Helper.print(rx)));
        System.out.println(
            "--------------------------------------------------------------------------------------------------------------------------------\n");
        return response;
    }

    private void finalizeReset()
    {
        if (mode == Mode.SIM) {
            Helper.simulator.resetRuntime();
            install(DummyIssuerSecurityDomain.class);
            select(DummyIssuerSecurityDomain.class);
        } else if (mode == Mode.PHY) {
            // TODO: delete all applets
            select(DummyIssuerSecurityDomain.class);
        }
    }

    /*
    Here, i let the card decide for keyset. The card preferred keyset#3 (subtype
    1), but the offcard does not have keyset#3. The offcard is preparing
    keyset#1.

    We cannot know, what keyset# the card will chose. So the below is not an
    error as you can see the status word is 0x9000. The offcard on next request
    must therefore ready keyset#3 to succesfully do init-update.

    cm> dks 1 404142434445464748494a4b4c4d4e4F
    /mode echo=off trace=off verbose=off debug=off
    cm> init-update
     => 80 50 00 00 08 8C 8D 43 56 E4 6C AC BE 00          .P.....CV.l...
     (18729 usec)
     <= 00 00 83 09 18 02 30 57 05 2F 03 02 00 29 A2 EA    ......0W./...)..
        68 DA 48 EE 18 B4 3B 4D 72 48 60 33 90 00          h.H...;MrH`3..
    Status: No Error
    No such key: 3/1
            at com.ibm.jc.AppletKeys.getKey(Unknown Source)
            at com.ibm.jc.SCPversion02.getSCPKeys(Unknown Source)
            at com.ibm.jc.SCPversion02.processInitializeUpdateResponse(Unknown
    Source) at com.ibm.jc.OPApplet.initializeUpdate(Unknown Source) at
    com.ibm.jc.tools.o.if(Unknown Source) at
    com.ibm.jc.tools.OPAppletPlugin.initUpdateCMD(Unknown Source) at
    com.ibm.jc.tools.OPAppletPlugin.execute(Unknown Source) at
    com.ibm.jc.tools.SecurityDomainPlugin.execute(Unknown Source) at
    com.ibm.jc.tools.CardManagerPlugin.execute(Unknown Source) at
    com.ibm.jc.tools.JCShell.executeCommand(Unknown Source) at
    com.ibm.jc.tools.JCShell.interactiveInput(Unknown Source) at
    com.ibm.jc.tools.JCShell.main(Unknown Source) jcshell: Error code: -8
    (Failed (no diagnosis)) jcshell: Command failed: No such key: 3/1 
    cm> print-k 
    1/1/DES-ECB/404142434445464748494A4B4C4D4E4F
    1/2/DES-ECB/404142434445464748494A4B4C4D4E4F
    1/3/DES-ECB/404142434445464748494A4B4C4D4E4F
    */
    public byte[] initializeUpdate()
    {
        byte kvno = 0x00;
        return initializeUpdate(kvno);
    }

    public byte[] initializeUpdate(byte kvno)
    {
        this.offCardSecurityState.resetSecurity();

        SecureRandom random = new SecureRandom();
        random.nextBytes(this.offCardSecurityState.host_challenge);
        byte p1 = kvno;
        byte p2 = 0x00; // Must be always 0x00 GPCardSpec v2.3.1 E.5.1.4

        CommandAPDU command = new CommandAPDU(
            0x80, 0x50, p1, p2, this.offCardSecurityState.host_challenge);

        ResponseAPDU response = new ResponseAPDU(Helper.SW9000);

        try {
            response = Transmit(command);

            if (response.getSW() != 0x9000) {
                return response.getBytes();
            }

            byte[] cardresponse = response.getData();

            // Get the card's chosen kvno
            Util.arrayCopyNonAtomic(cardresponse,
                                    (short)10,
                                    this.offCardSecurityState.keyInfoResponse,
                                    (short)0,
                                    (byte)2);

            // Use keyset kvno chosen by card
            byte index = this.offCardSecurityState.keyInfoResponse[0];

            // Get 2 bytes sequence number
            byte[] seq = new byte[2];
            Util.arrayCopyNonAtomic(
                cardresponse, (short)12, seq, (short)0, (byte)seq.length);

            // Save card_challenge!
            Util.arrayCopyNonAtomic(
                cardresponse,
                (short)12,
                this.offCardSecurityState.card_challenge,
                (short)0,
                (byte)this.offCardSecurityState.card_challenge.length);

            byte[] card_cryptogram = new byte[8];
            // Save card_cryptogram
            Util.arrayCopyNonAtomic(cardresponse,
                                    (short)20,
                                    card_cryptogram,
                                    (short)0,
                                    (byte)card_cryptogram.length);

            byte[] kEnc = null;
            byte[] kMac = null;
            byte[] kDek = null;

            if (index == (byte)0xFF) {
                kEnc = Helper.nxpDefaultKey;
                kMac = Helper.nxpDefaultKey;
                kDek = Helper.nxpDefaultKey;

            } else {
                try {
                    kEnc = this.offCardSecurityState.keys[index - 1].kEnc;
                    kMac = this.offCardSecurityState.keys[index - 1].kMac;
                    kDek = this.offCardSecurityState.keys[index - 1].kDek;
                    _o.o_(kEnc);
                } catch (java.lang.ArrayIndexOutOfBoundsException e) {

                    String info = String.format(
                        "Command failed: No such key: 0x%02X/0x%02X",
                        kvno,
                        index);
                    System.out.println(info);
                    return cardresponse;
                }
            }

            sENC = CryptoAPI.deriveSCP02SessionKey(
                kEnc, seq, CryptoAPI.constENC);
            sMAC = CryptoAPI.deriveSCP02SessionKey(
                kMac, seq, CryptoAPI.constMAC);
            sDEK = CryptoAPI.deriveSCP02SessionKey(
                kDek, seq, CryptoAPI.constDEK);

            this.offCardSecurityState.sessionENC = sENC;
            this.offCardSecurityState.sessionMAC = sMAC;
            this.offCardSecurityState.sessionDEK = sDEK;

            byte[] hostcard_challenge
                = Helper.arrayConcat(this.offCardSecurityState.host_challenge,
                                     this.offCardSecurityState.card_challenge);
            byte[] cgram = CryptoAPI.calcCryptogram(hostcard_challenge, sENC);

            if (Arrays.equals(cgram, card_cryptogram)) {
                System.out.println("--cryptogram match--");
                this.offCardSecurityState.bInitUpdated = true;
            } else {

                System.out.println("Error code: -5 (Authentication failed)");
                System.out.println("Wrong response APDU: "
                                   + Helper.print(response.getBytes()));
                System.out.println("Error message: Card cryptogram invalid");
            }

        } catch (AssertionError e) {
            // e.printStackTrace();
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // throw new IllegalStateException("OffCard: key not found");
        }

        return response.getBytes();
    }

    public void externalAuthenticate(byte securityLevel)
    {
        if (this.offCardSecurityState.bInitUpdated == false) {
            System.out.println("Error code: -7 (Illegal state)");
            System.out.println(
                "Command failed: No SCP protocol found, need to run init-update first");
        }

        byte p1 = securityLevel;
        byte p2 = 0x00; // Must be always 0x00 (GPCardspec v2.3.1 E.5.2.4)

        if ((securityLevel & Helper.GP.C_DECRYPTION) != 0) { // if ENC is set
            p1 = (byte)(p1 | Helper.GP.C_MAC); // then set MAC
        }

        byte[] cardhost_challenge
            = Helper.arrayConcat(this.offCardSecurityState.card_challenge,
                                 this.offCardSecurityState.host_challenge);

        // des_ede_cbc(resize8(sENC),nullbytes8, [card_challenge +
        // host_challenge]);
        byte[] host_cryptogram
            = CryptoAPI.calcCryptogram(cardhost_challenge, sENC);
        ////////////////////???
        byte[] data = host_cryptogram;

        ByteArrayOutputStream macData = new ByteArrayOutputStream();
        macData.write(0x84);
        macData.write(0x82);
        macData.write(p1);
        macData.write(p2);
        macData.write(data.length + 8);
        try {
            macData.write(data);
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        byte[] icv;
        if (Arrays.equals(_icv, CryptoAPI.NullBytes8)) {
            icv = _icv;
        } else {
            icv = CryptoAPI.updateIV(_icv, sMAC);
        }
        byte[] t = macData.toByteArray();
        byte[] mac = CryptoAPI.computeMAC(macData.toByteArray(), icv, sMAC);
        byte[] newData = Helper.arrayConcat(data, mac);

        CommandAPDU command
            = new CommandAPDU(0x84, 0x82, p1, p2, newData); // add needsLE logic
        ResponseAPDU response;
        try {
            response = Transmit(command);
            Assert.assertEquals(
                0x9000, response.getSW(), "externalAuthenticate");
            if (response.getSW() == 0x9000) {
                this.offCardSecurityState.securityLevel
                    = p1; // p1 is effective securityLevel
                this.offCardSecurityState.bInitUpdated = false;
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public byte[] selectAppletWithResult(byte[] id_bytes) throws SystemException
    {
        byte[] result = {(byte)0x6A, (byte)0xA2};
        ResponseAPDU response = null;
        CommandAPDU command = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, id_bytes);
        try {
            response = channel.transmit(command);
        } catch (CardException e) {
            e.printStackTrace();
        }
        result = response.getBytes();
        return result;
    }
}

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

import org.idpass.offcard.applet.DummyISDApplet;
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

import org.globalplatform.SecureChannel;

public class OffCard
{
    // Keys inside off-card
    private static SCP02Keys offcardKeys[] = {
        new SCP02Keys("404142434445464748494a4b4c4d4e4F", // 1
                      "404142434445464748494a4b4c4d4e4F",
                      "404142434445464748494a4b4c4d4e4F"),
        new SCP02Keys("DEC0DE0102030405060708090A0B0C0D", // 2
                      "DEC0DE0102030405060708090A0B0C0D",
                      "DEC0DE0102030405060708090A0B0C0D"),
        new SCP02Keys("CAFEBABE0102030405060708090A0B0C", // 3
                      "CAFEBABE0102030405060708090A0B0C",
                      "CAFEBABE0102030405060708090A0B0C"),
        new SCP02Keys("C0FFEE0102030405060708090A0B0C0D", // 4
                      "C0FFEE0102030405060708090A0B0C0D",
                      "C0FFEE0102030405060708090A0B0C0D"),
    };

    private static OffCard instance;

    public static void reInitialize()
    {
        instance = null;
        SCP02.reInitialize();
        Helper.reInitialize();
    }

    public static OffCard getInstance()
    {
        if (instance == null) {
            return getInstance(Helper.getjcardsimChannel());
        }
        return instance;
    }

    public static OffCard getInstance(CardChannel chan)
    {
        if (instance == null) {
            // install & select DummyISDApplet
            instance = new OffCard(chan);
        }

        return instance;
    }

    private CardChannel channel;
    // private byte[] icv;
    private String currentSelected;
    private Invariant Assert = new Invariant();
    private SCP02 scp02;
    private Mode mode;

    public Mode getMode()
    {
        return mode;
    }

    private OffCard(CardChannel channel)
    {
        this.channel = channel;
        // icv = CryptoAPI.NullBytes8.clone();

        // This is the off-card side of the secure channel
        scp02 = new SCP02(offcardKeys);

        String s = channel.getClass().getCanonicalName();
        if (s.equals(
                "com.licel.jcardsim.smartcardio.CardSimulator.CardChannelImpl")) {
            mode = Mode.SIM;
            Helper.simulator.resetRuntime();
            INSTALL(DummyISDApplet.class);
            select(DummyISDApplet.class);
        } else {
            mode = Mode.PHY;
            select(DummyISDApplet.class);
        }
    }

    public byte[] SELECT_CM()
    {
        byte[] retval = select(DummyISDApplet.class);
        return retval;
    }

    public void ATR()
    {
        if (mode == Mode.SIM) {
            // simulator.reset(); // DO NOT CALL THIS method!
            // This resets security level of previously selected applet
            select(DummyISDApplet.class); // invoke security reset
        } else if (mode == Mode.PHY) {
            // card.getATR(); // ?
            select(DummyISDApplet.class); // invoke security reset
        }
    }

    public Object INSTALL(Class<? extends javacard.framework.Applet> cls)
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

        Object inst = null;

        try {
            Method getinstance = cls.getMethod("getInstance");
            try {
                inst = getinstance.invoke(null);
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            } catch (IllegalArgumentException e) {
                e.printStackTrace();
            } catch (InvocationTargetException e) {
                e.printStackTrace();
            }
        } catch (NoSuchMethodException | SecurityException e) {
            e.printStackTrace();
        }

        return inst;
    }

    public byte[] select(Class<? extends javacard.framework.Applet> cls)
    {
        this.scp02.resetSecurity();

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

        return result;
    }

    public ResponseAPDU Transmit(CommandAPDU apdu)
    {
        byte sl = scp02.getSecurityLevel();

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

            if ((sl & SecureChannel.AUTHENTICATED) != 0
                || (sl & SecureChannel.C_MAC) != 0
                || (sl & SecureChannel.C_DECRYPTION) != 0) {
                cla = (byte)(cla | scp02.MASK_SECURED);
            }

            newData = data.clone();
            CommandAPDU command = new CommandAPDU(cla, ins, p1, p2, newData);

            response = channel.transmit(command);
            rx = response.getBytes();

        } catch (CardException e) {
            rx = response.getBytes();
        }
        System.out.println(
            "\n----------------------------------- OffCard::Transmit -----------------------------------------");
        System.out.println(currentSelected + ": [" + Helper.printsL(sl) + "]");
        System.out.println(String.format("=> %s", Helper.print(tx)));
        System.out.println(String.format("<= %s", Helper.print(rx)));
        Helper.printsL(sl);
        System.out.println(
            "-----------------------------------------------------------------------------------------------");
        return response;
    }

    public byte[] INITIALIZE_UPDATE()
    {
        byte kvno = 0x00;
        return INITIALIZE_UPDATE(kvno);
    }

    public byte[] INITIALIZE_UPDATE(byte kvno)
    {
        scp02.resetSecurity();

        SecureRandom random = new SecureRandom();
        random.nextBytes(scp02.host_challenge);
        byte p1 = kvno;
        byte p2 = 0x00; // Must be always 0x00 GPCardSpec v2.3.1 E.5.1.4

        CommandAPDU command
            = new CommandAPDU(0x80, 0x50, p1, p2, scp02.host_challenge);

        ResponseAPDU response = new ResponseAPDU(Helper.SW9000);

        try {
            response = Transmit(command);

            if (response.getSW() != 0x9000) {
                return response.getBytes();
            }

            byte[] cardresponse = response.getData();

            // receive card's key information
            Util.arrayCopyNonAtomic(
                cardresponse, (short)10, this.scp02.keyInfo, (short)0, (byte)2);

            // from keyInfo, get keyset# chosen by card
            byte index = this.scp02.keyInfo[0];

            // Save card_challenge!
            Util.arrayCopyNonAtomic(cardresponse,
                                    (short)12,
                                    this.scp02.card_challenge,
                                    (short)0,
                                    (byte)this.scp02.card_challenge.length);

            byte[] seq = new byte[2];
            seq[0] = scp02.card_challenge[0];
            seq[1] = scp02.card_challenge[1];

            byte[] cryptogram1 = new byte[8];

            // Read cryptogram calculated by card
            Util.arrayCopyNonAtomic(cardresponse,
                                    (short)20,
                                    cryptogram1,
                                    (short)0,
                                    (byte)cryptogram1.length);

            byte[] hostcard_challenge = Helper.arrayConcat(
                scp02.host_challenge, scp02.card_challenge);

            if (scp02.setKeyIndex(index, seq) == false) {
                String info = String.format(
                    "Command failed: No such key: 0x%02X/0x%02X", kvno, index);
                System.out.println(info);
                return cardresponse;
            }

            byte[] cryptogram2 = scp02.calcCryptogram(hostcard_challenge);

            if (Arrays.equals(cryptogram1, cryptogram2)) {
                this.scp02.bInitUpdated = true;
            } else {
                System.out.println("Error code: -5 (Authentication failed)");
                System.out.println("Wrong response APDU: "
                                   + Helper.print(response.getBytes()));
                System.out.println("Error message: Card cryptogram invalid");
                _o.o_(response.getBytes(), "INITIALIZE_UPDATE FAILED");
            }

        } catch (AssertionError e) {
            // e.printStackTrace();
        } catch (java.lang.ArrayIndexOutOfBoundsException e) {
            // throw new IllegalStateException("OffCard: key not found");
        }

        return response.getBytes();
    }

    public byte[] EXTERNAL_AUTHENTICATE(byte securityLevel)
    {
        byte[] cardresponse = {};

        if (scp02.bInitUpdated == false) {
            scp02.resetSecurity();
            System.out.println("Error code: -7 (Illegal state)");
            System.out.println(
                "Command failed: No SCP protocol found, need to run init-update first");

            return cardresponse;
        }

        byte p1 = securityLevel;
        byte p2 = 0x00; // Must be always 0x00 (GPCardspec v2.3.1 E.5.2.4)

        if ((securityLevel & SCP02.C_DECRYPTION) != 0) { // if ENC is set
            p1 = (byte)(p1 | SCP02.C_MAC); // then set MAC
        }

        byte[] cardhost_challenge
            = Helper.arrayConcat(scp02.card_challenge, scp02.host_challenge);

        byte[] cardhost_cryptogram = scp02.calcCryptogram(cardhost_challenge);
        ////////////////////???
        byte[] data = cardhost_cryptogram;

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

        byte[] mac = scp02.computeMac(macData.toByteArray());
        byte[] newData = Helper.arrayConcat(data, mac);

        CommandAPDU command
            = new CommandAPDU(0x84, 0x82, p1, p2, newData); // add needsLE logic
        ResponseAPDU response;
        try {
            response = Transmit(command);
            cardresponse = response.getData();

            if (response.getSW() == 0x9000) {
                scp02.securityLevel
                    = (byte)(scp02.securityLevel | p1 | SCP02.AUTHENTICATED);
                scp02.bInitUpdated = false;

            } else {
                _o.o_(cardresponse, "EXTERNAL_AUTHENTICATE FAILED");
            }

        } catch (AssertionError e) {
            e.printStackTrace();
        }

        return cardresponse;
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

    public boolean tmpCheck01(int cla)
    {
        byte sl = scp02.getSecurityLevel();
        boolean flag = true;

        if ((cla & SCP02.MASK_SECURED) > 0) {
            if (((sl & SecureChannel.AUTHENTICATED) == 0)
                || ((sl & SecureChannel.C_MAC) == 0)) {
                scp02.resetSecurity();
                return false;
            }

            if (((sl & SecureChannel.AUTHENTICATED) == 0)
                || ((sl & SecureChannel.C_DECRYPTION) == 0)) {
                scp02.resetSecurity();
                return false;
            }

        } else {
            if ((sl & SecureChannel.AUTHENTICATED) != 0) {
                scp02.resetSecurity();
                return false;
            }
        }

        return flag;
    }

    public boolean tmpCheck03(byte kvno)
    {
        boolean flag = true;

        if (kvno != 0xFF && kvno > scp02.userKeys.length) {
            return false;
        }

        return flag;
    }

    protected boolean isCheckC_MAC(int cla)
    {
        byte sl = scp02.getSecurityLevel();

        if ((cla & SCP02.MASK_SECURED) > 0) {
            if (((sl & SecureChannel.AUTHENTICATED) == 0)
                || ((sl & SecureChannel.C_MAC) == 0)) {
                // resetSecurity();
                // ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                System.out.println("checkmac1");
            }
            return true;
        } else {
            if ((sl & SecureChannel.AUTHENTICATED) != 0) {
                // resetSecurity();
                // ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                System.out.println("checkmac2");
            }
            return false;
        }
    }

    protected boolean isCheckC_DECRYPTION(int cla)
    {
        byte sl = scp02.getSecurityLevel();

        if ((cla & SCP02.MASK_SECURED) > 0) {
            if (((sl & SecureChannel.AUTHENTICATED) == 0)
                || ((sl & SecureChannel.C_DECRYPTION) == 0)) {
                // resetSecurity();
                // ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                System.out.println("checkenc1");
            }
            return true;
        } else {
            if ((sl & SecureChannel.AUTHENTICATED) != 0) {
                // resetSecurity();
                // ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                System.out.println("checkenc2");
            }
            return false;
        }
    }
}

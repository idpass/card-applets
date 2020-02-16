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

import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.Util;
// import javacardx.crypto.Cipher; // @watch@

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

// clang-format off
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
    // clang-format on

    public static void reInitialize()
    {
        instance = null;
        SCP02.reInitialize();
        Helper.reInitialize();
    }

    public static OffCard getInstance()
    {
        if (instance == null) {
            try {
                return getInstance(Helper.getjcardsimChannel());
            } catch (CardException e) {

            }
        }
        return instance;
    }

    public static OffCard getInstance(CardChannel chan)
    {
        if (instance == null) {
            // install & select DummyISDApplet
            if (chan != null) {
                instance = new OffCard(chan);
            }
        }

        return instance;
    }

    private CardChannel channel;
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

        // This is the off-card side of the secure channel
        scp02 = new SCP02(offcardKeys, "offcard");

        String s = channel.getClass().getCanonicalName();
        if (s.equals(
                "com.licel.jcardsim.smartcardio.CardSimulator.CardChannelImpl")) {
            mode = Mode.SIM;
            Helper.simulator.resetRuntime();
            INSTALL(DummyISDApplet.class);
            select(DummyISDApplet.class);
        } else {
            mode = Mode.PHY;
            // TODO: Use paljak's way to discover the CM
            // and select it without involving any AID values
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
        String strId = cfg.instanceAID();
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

        String strId = cfg.instanceAID();
        byte[] id_bytes = Hex.decode(strId);
        currentSelected = cls.getCanonicalName();

        if (mode == Mode.SIM) {
            result = Helper.simulator.selectAppletWithResult(
                AIDUtil.create(id_bytes)); // @diff1_@
        } else if (mode == Mode.PHY) {
            if (currentSelected.equals(
                    "org.idpass.offcard.applet.DummyISDApplet")) {
                // Physical cards can have different CM AID
                byte[] aid1 = Hex.decode("A0000001510000");
                byte[] aid2 = Hex.decode("D1560001320D0101");

                result = selectAppletWithResult(aid1);
                ResponseAPDU r = new ResponseAPDU(result);
                if (r.getSW() != 0x9000) {
                    result = selectAppletWithResult(aid2); // try this one
                }
            } else {
                result = selectAppletWithResult(id_bytes); // @diff1@
            }
        }

        ResponseAPDU response = new ResponseAPDU(result);
        Assert.assertEquals(response.getSW(), 0x9000, "OffCard::select");

        return result;
    }

    public byte[] Transmit(String rawbytes)
    {
        byte[] cmd = Hex.decode(rawbytes);
        CommandAPDU command = new CommandAPDU(cmd);
        ResponseAPDU response = Transmit(command);
        return response.getBytes();
    }

    public ResponseAPDU Transmit(CommandAPDU apdu)
    {
        boolean flag = false;
        byte sl = scp02.getSecurityLevel();

        ResponseAPDU response = new ResponseAPDU(Helper.SW6701);

        byte[] tx = apdu.getBytes();
        byte[] rx = {};

        byte cla = (byte)apdu.getCLA();
        final byte ins = (byte)apdu.getINS();
        final byte p1 = (byte)apdu.getP1();
        final byte p2 = (byte)apdu.getP2();
        final byte[] data = apdu.getData();
        byte origCLA = cla;

        // byte[] finalData = data;
        byte[] newData = data;
        byte[] M = {};

        int newLc = apdu.getNc();

        ByteArrayOutputStream t = new ByteArrayOutputStream();
        int le = apdu.getNe();

        try {
            t.write(data);
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        if ((sl & SCP02.AUTHENTICATED) != 0
            || (sl & SCP02.C_MAC) != 0
            || (sl & SCP02.C_DECRYPTION) != 0) {
            cla = (byte)(cla | SCP02.MASK_SECURED);
            t.reset();

            try {
                t.write(cla);
                t.write(ins);
                t.write(p1);
                t.write(p2);

                if ((sl & SCP02.C_MAC) != 0) {
                    newLc = newLc + 8;

                    t.write(newLc);
                    t.write(data);

                    byte[] input = t.toByteArray();
                    M = scp02.computeMac(input);
                    newData = Helper.arrayConcat(data, M);
                    t.reset();
                }

                if ((sl & SCP02.C_DECRYPTION) != 0 && data.length > 0) {
                    byte[] dataPadded = CryptoAPI.pad80(
                        data, 8); // still needed due to len calculation!?
                    t.write(dataPadded);
                    newLc += t.size() - data.length;

                    newData = CryptoAPI.encryptData(
                        data, scp02.sessionENC); // don't pad twice

                    flag = true;
                    t.reset();
                }

                t.write(cla);
                t.write(ins);
                t.write(p1);
                t.write(p2);

                // TODO: clean-up logic later to improve
                if (newLc > 0) {
                    t.write(newLc);
                    t.write(newData);
                }

                if (flag == true) {
                    if (M.length > 0) {
                        t.write(M);
                    }
                }

                if (le > 0) {
                    t.write(le);
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        byte[] wrapCmdData = t.toByteArray();
        CommandAPDU command = null;

        if (M.length > 0) {
            command = new CommandAPDU(wrapCmdData);
        } else {
            command = new CommandAPDU(origCLA, ins, p1, p2, wrapCmdData);
        }

        try {
            response = channel.transmit(command);
            rx = response.getBytes();
        } catch (CardException e) {
            rx = response.getBytes();
        }

        byte[] tx2 = command.getBytes();

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

        response = Transmit(command);

        if (response.getSW() != 0x9000) {
            return response.getBytes();
        }

        byte[] cardresponse = response.getData();
        byte[] keyInfo = new byte[2];
        // receive card's key information
        Util.arrayCopyNonAtomic(
            cardresponse, (short)10, keyInfo, (short)0, (byte)2);

        // from keyInfo, get keyset# chosen by card
        byte index = keyInfo[0];
        byte proto = keyInfo[1];

        if (proto != 0x02) {
            ISOException.throwIt((short)ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Save card_challenge!
        Util.arrayCopyNonAtomic(cardresponse,
                                (short)12,
                                this.scp02.card_challenge,
                                (short)0,
                                (byte)this.scp02.card_challenge.length);

        byte[] seq = new byte[2];
        seq[0] = scp02.card_challenge[0];
        seq[1] = scp02.card_challenge[1];

        byte[] cryptogram = new byte[8];

        // Read cryptogram calculated by card
        Util.arrayCopyNonAtomic(cardresponse,
                                (short)20,
                                cryptogram,
                                (short)0,
                                (byte)cryptogram.length);

        byte[] hostcard_challenge
            = Helper.arrayConcat(scp02.host_challenge, scp02.card_challenge);

        if (scp02.setKeyIndex(index, seq) == false) {
            return cardresponse;
        }

        byte[] hostcard_cryptogram = scp02.calcCryptogram(hostcard_challenge);

        if (Arrays.equals(cryptogram, hostcard_cryptogram)) {
            this.scp02.bInitUpdated = true;
        } else {

        }

        return response.getBytes();
    }

    public byte[] EXTERNAL_AUTHENTICATE(byte securityLevel)
    {
        byte[] cardresponse = {};

        if (scp02.bInitUpdated == false) {
            scp02.resetSecurity();
            cardresponse = new ResponseAPDU(Helper.SW6985).getBytes();
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

        response = Transmit(command);
        cardresponse = response.getBytes();

        if (response.getSW() == 0x9000) {
            scp02.securityLevel
                = (byte)(scp02.securityLevel | p1 | SCP02.AUTHENTICATED);
            scp02.bInitUpdated = false;
            // scp02.icv = CryptoAPI.NullBytes8.clone();

        } else {

        }

        return cardresponse;
    }

    public byte[] selectAppletWithResult(
        byte[] id_bytes) // throws SystemException
    {
        byte[] result = {(byte)0x6A, (byte)0xA2};
        ResponseAPDU response = null;
        CommandAPDU command = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, id_bytes);
        response = Transmit(command);
        result = response.getBytes();
        return result;
    }

    public void close()
    {
        Invariant.check();
    }

    /*
    // Try to find GlobalPlatform from a card
    public byte[] discover()
    {
        byte[] ret = {};

        // Try the default
        final CommandAPDU command = new CommandAPDU(
            ISO7816.CLA_ISO7816,
            ISO7816.INS_SELECT,
            0x04,
            0x00,
            256);

        ResponseAPDU response = Transmit(command);

        // Unfused JCOP replies with 0x6A82 to everything
        if (response.getSW() == 0x6A82) {
            // If it has the identification AID, it probably is an unfused JCOP
            byte[] identify_aid = Hex.decode("A000000167413000FF");

            CommandAPDU identify = new CommandAPDU(
                ISO7816.CLA_ISO7816,
                ISO7816.INS_SELECT,
                0x04,
                0x00,
                identify_aid,
                256);

            ResponseAPDU identify_resp = channel.transmit(identify);
            byte[] identify_data = identify_resp.getData();
            // Check the fuse state
            if (identify_data.length > 15) {
                if (identify_data[14] == 0x00) {
                    //throw new GPException("Unfused JCOP detected");
                    return ret;
                }
            }
        }

        // SmartJac UICC
        if (response.getSW() == 0x6A87) {
            // Try the default
            //return connect(channel, new AID(GPData.defaultISDBytes));
            return Hex.decode("A000000151000000");

        }

        final BerTlvs tlvs;
        try {
            // Detect security domain based on default select
            BerTlvParser parser = new BerTlvParser();
            tlvs = parser.parse(response.getData());
        } catch (ArrayIndexOutOfBoundsException | IllegalStateException e) {
            // XXX: Exists a card, which returns plain AID as response
            //logger.warn("Could not parse SELECT response: " + e.getMessage());
            //throw new GPDataException("Could not auto-detect ISD AID",
    response.getData()); return ret;
        }

        BerTlv fcitag = tlvs.find(new BerTag(0x6F));
        if (fcitag != null) {
            BerTlv isdaid = fcitag.find(new BerTag(0x84));
            // XXX: exists a card that returns a zero length AID in template
            if (isdaid != null && isdaid.getBytesValue().length > 0) {
                return isdaid.getBytesValue();
            }
        }

        return ret;
    }
    */
}

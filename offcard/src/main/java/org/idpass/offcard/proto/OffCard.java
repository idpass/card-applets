package org.idpass.offcard.proto;

import java.io.ByteArrayOutputStream;

import java.io.IOException;
import java.util.List;

import java.security.SecureRandom;

import java.util.Arrays;

//import org.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.idpass.offcard.applet.DummyIssuerSecurityDomain;
import org.idpass.offcard.misc.Helper;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc._o;

// import org.idpass.offcard.io.CardChannel;  // check this !!!

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;

// import javacard.framework.AID;
import javacard.framework.Util;
// import javacardx.crypto.Cipher; // not this one!

public abstract class OffCard
{
    private static CardSimulator simulator;
    private static CardTerminal terminal;
    private static Card card;
    private static CardChannel channel;

    private static byte[] kEnc = Hex.decode("404142434445464748494a4b4c4d4e4F");
    private static byte[] kMac = Hex.decode("404142434445464748494a4b4c4d4e4F");
    private static byte[] kDek = Hex.decode("404142434445464748494a4b4c4d4e4F");

    private static byte[] sENC;
    private static byte[] sMAC;
    private static byte[] sDEK;

    private static byte[] _card_challenge = new byte[8]; // Card generates this
    private static byte[] _host_challenge
        = new byte[8]; // OffCard generates this
    private static byte[] kvno_prot = new byte[2];
    private static byte[] _card_cryptogram = new byte[8];

    private static byte[] _icv = CryptoAPI.NullBytes8.clone();

    private static String opMode = null;
    private static String currentSelected;

    private static Invariant Assert;

    static
    {
        Assert = new Invariant();
        opMode = System.getProperty("opmode");

        if (opMode == null) {
            simulator = new CardSimulator();
            terminal = CardTerminalSimulator.terminal(simulator);
            try {
                card = terminal.connect("T=1");
                channel = card.getBasicChannel();
                sysInitialize();
            } catch (CardException e) {
                e.printStackTrace();
            }
        } else if (opMode.equals("pcsc")) {
            TerminalFactory factory = TerminalFactory.getDefault();
            try {
                List<CardTerminal> terminals = factory.terminals().list();
                terminal = terminals.get(1);
                card = terminal.connect("*");
                channel = card.getBasicChannel();
            } catch (CardException e) {
                e.printStackTrace();
            }
        }
    }

    public static byte[] select_cm()
    {
        byte[] retval = select(DummyIssuerSecurityDomain.class);
        return retval;
    }

    public static void ATR()
    {
        if (opMode == null) {
            // simulator.reset(); // DO NOT CALL THIS method!
            // This resets security level of previously selected applet
            select(DummyIssuerSecurityDomain.class); // invoke security reset
        } else {
            // card.getATR(); // ?
            select(DummyIssuerSecurityDomain.class); // invoke security reset
        }
    }

    public static void install(Class<? extends javacard.framework.Applet> cls)
    {
        if (opMode == null) {
            IdpassConfig cfg = cls.getAnnotation(IdpassConfig.class);

            byte[] bArray = null;
            String strId = cfg.appletInstanceAID();
            byte[] id_bytes = Hex.decode(strId);
            byte[] installParams = cfg.installParams();
            byte[] privileges = cfg.privileges();

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

            simulator.installApplet(AIDUtil.create(id_bytes),
                                    cls,
                                    bArray,
                                    (short)0,
                                    (byte)bArray.length);

        } else if (opMode.equals("pcsc")) {
            // TODO:
        } else if (opMode.equals("nfc")) {
            // TODO:
        }
    }

    public static byte[] select(Class<? extends javacard.framework.Applet> cls)
    {
        byte[] result = new byte[] {(byte)0x6A, (byte)0xA2};

        IdpassConfig cfg = cls.getAnnotation(IdpassConfig.class);

        String strId = cfg.appletInstanceAID();
        byte[] id_bytes = Hex.decode(strId);
        currentSelected = cls.getCanonicalName();

        if (opMode == null) {
            result = simulator.selectAppletWithResult(AIDUtil.create(id_bytes));
        } else if (opMode.equals("pcsc")) {
            ResponseAPDU answer
                = Transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, id_bytes));
            result = answer.getBytes();
        } else if (opMode.equals("nfc")) {
            // TODO:
        }
        byte[] sw = new byte[2];
        System.arraycopy(result, result.length - 2, sw, 0, sw.length);
        String s = String.format("SELECT %s ERROR", currentSelected);
        Assert.assertEquals(sw, Helper.SW9000, s);
        return result;
    }

    public static ResponseAPDU Transmit(CommandAPDU apdu)
    {
        ResponseAPDU response = new ResponseAPDU(new byte[] {
            (byte)0x67,
            (byte)0x01,
        });

        try {
            // ByteBuffer buf;
            response = channel.transmit(apdu);
            if (response.getSW() != 0x9000) {
                System.out.println(
                    "ERROR: " + currentSelected
                    + String.format(" 0x%04x", response.getSW()));
            }

            // boolean orig = Invariant.cflag;
            // Invariant.cflag = false;
            // Assert.assertEquals(0x9000, response.getSW(),
            // "OffCard::Transmit");
            // Invariant.cflag = orig;
        } catch (CardException e) {
            e.printStackTrace();
        }
        return response;
    }

    public static void sysInitialize()
    {
        if (opMode == null) {
            simulator.resetRuntime();
            install(DummyIssuerSecurityDomain.class);
            select(DummyIssuerSecurityDomain.class);
            currentSelected
                = DummyIssuerSecurityDomain.class.getCanonicalName();
        } else {
            // TODO: delete all applets
            select(DummyIssuerSecurityDomain.class);
        }
    }

    public static void initializeUpdate()
    {
        byte kvno = 0x00;
        initializeUpdate(kvno);
    }

    public static void initializeUpdate(byte kvno)
    {
        SecureRandom random = new SecureRandom();
        random.nextBytes(_host_challenge);
        byte p1 = kvno;
        byte p2 = 0x00; // Must be always 0x00 GPCardSpec v2.3.1 E.5.1.4

        CommandAPDU command
            = new CommandAPDU(0x80, 0x50, p1, p2, _host_challenge);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "initializeUpdate");
            byte[] cardresponse = response.getData();

            // Save kvno_prot
            Util.arrayCopyNonAtomic(
                cardresponse, (short)10, kvno_prot, (short)0, (byte)2);

            // Get 2 bytes sequence number
            byte[] seq = new byte[2];
            Util.arrayCopyNonAtomic(
                cardresponse, (short)12, seq, (short)0, (byte)2);

            // Save card_challenge!
            Util.arrayCopyNonAtomic(
                cardresponse, (short)12, _card_challenge, (short)0, (byte)8);
            // Save card_cryptogram
            Util.arrayCopyNonAtomic(
                cardresponse, (short)20, _card_cryptogram, (short)0, (byte)8);

            sENC = CryptoAPI.deriveSCP02SessionKey(
                kEnc, seq, CryptoAPI.constENC);
            sMAC = CryptoAPI.deriveSCP02SessionKey(
                kMac, seq, CryptoAPI.constMAC);
            sDEK = CryptoAPI.deriveSCP02SessionKey(
                kDek, seq, CryptoAPI.constDEK);

            byte[] hostcard_challenge
                = Helper.arrayConcat(_host_challenge, _card_challenge);
            byte[] cgram = CryptoAPI.calcCryptogram(hostcard_challenge, sENC);

            if (Arrays.equals(cgram, _card_cryptogram)) {
                System.out.println("--cryptogram match--");
            }

            Assert.assertEquals(
                cgram, _card_cryptogram, "initalizeUpdate:cryptogram");

        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public static void externalAuthenticate(byte securityLevel)
    {
        byte p1 = securityLevel;
        byte p2 = 0x00; // Must be always 0x00 (GPCardspec v2.3.1 E.5.2.4)

        if ((securityLevel & 0b0010) != 0) { // if ENC is set
            p1 = (byte)(p1 | 0b0001); // then set MAC
        }

        byte[] cardhost_challenge
            = Helper.arrayConcat(_card_challenge, _host_challenge);

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
            response = OffCard.Transmit(command);
            Assert.assertEquals(
                0x9000, response.getSW(), "externalAuthenticate");
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }
}

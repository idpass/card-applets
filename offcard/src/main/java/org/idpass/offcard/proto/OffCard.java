package org.idpass.offcard.proto;

import java.io.ByteArrayOutputStream;

import java.io.IOException;
import java.util.List;
import java.security.SecureRandom;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.idpass.offcard.applet.DummyIssuerSecurityDomain;
import org.idpass.offcard.misc.Helper;
import org.idpass.offcard.misc.Helper.Link;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.Util;
// import javacardx.crypto.Cipher; // @watch@

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class OffCard
{
    private static OffCard instance;

    private static CardSimulator simulator;
    private static CardTerminal terminal;
    private static Card card;
    private CardChannel channel;

    private static final byte[] _icv = CryptoAPI.NullBytes8.clone();

    private byte[] kEnc = Hex.decode("404142434445464748494a4b4c4d4e4F");
    private byte[] kMac = Hex.decode("404142434445464748494a4b4c4d4e4F");
    private byte[] kDek = Hex.decode("404142434445464748494a4b4c4d4e4F");

    private byte[] sENC;
    private byte[] sMAC;
    private byte[] sDEK;

    private byte[] _card_challenge = new byte[8]; // Card generates this
    private byte[] _host_challenge = new byte[8]; // OffCard generates this
    private byte[] kvno_prot = new byte[2];
    private byte[] _card_cryptogram = new byte[8];

    private String currentSelected;

    private Invariant Assert = new Invariant();

    private boolean _bInitUpdated = false;
    private byte _securityLevel = 0x00;
    private byte _kvno = (byte)0xFF;

    private org.globalplatform.SecureChannel secureChannel;
    private Link link;

    public Link getLink()
    {
        return link;
    }

    private OffCard(Link link)
    {
        this.link = link;

        if (link == Link.SIM) {
            simulator = new CardSimulator();
            terminal = CardTerminalSimulator.terminal(simulator);
            try {
                card = terminal.connect("T=1");
                channel = card.getBasicChannel();
            } catch (CardException e) {
                e.printStackTrace();
            }
        } else if (link == Link.WIRED) {
            TerminalFactory factory = TerminalFactory.getDefault();
            try {
                List<CardTerminal> terminals = factory.terminals().list();
                terminal = terminals.get(1);
                card = terminal.connect("*");
                channel = card.getBasicChannel();
            } catch (CardException e) {
                String msg
                    = "ERROR: USB card reader|" + e.getCause().getMessage();
                System.out.println(msg);
                System.exit(1);
            }
        } else if (link == Link.WIRELESS) {
            System.out.println("TODO: NFC");
            System.exit(1);
        } else {
            System.out.println("unrecognized link");
            System.exit(2);
        }

        init();
    }

    public static void reInitialize()
    {
        if (instance != null) {
            SCP02SecureChannel.count = 0;
            instance.init();
        }
    }

    public static OffCard getInstance()
    {
        if (instance == null) {
            String comlink = System.getProperty("comlink");
            Link linkType;

            if (comlink == null) {
                linkType = Link.SIM;
            } else if (comlink.equals("wired")) {
                linkType = Link.WIRED;
            } else {
                linkType = Link.WIRELESS;
            }

            instance = new OffCard(linkType);
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
        if (link == Link.SIM) {
            // simulator.reset(); // DO NOT CALL THIS method!
            // This resets security level of previously selected applet
            select(DummyIssuerSecurityDomain.class); // invoke security reset
        } else {
            // card.getATR(); // ?
            select(DummyIssuerSecurityDomain.class); // invoke security reset
        }
    }

    public void install(Class<? extends javacard.framework.Applet> cls)
    {
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

        if (link == Link.SIM) {
            simulator.installApplet(AIDUtil.create(id_bytes),
                                    cls,
                                    bArray,
                                    (short)0,
                                    (byte)bArray.length);

        } else if (link == Link.WIRED) {
            installApplet(AIDUtil.create(id_bytes),
                          cls,
                          bArray,
                          (short)0,
                          (byte)bArray.length);
        } else if (link == link.WIRELESS) {
            // TODO:
        }
    }

    public byte[] select(Class<? extends javacard.framework.Applet> cls)
    {
        byte[] result = new byte[] {(byte)0x6A, (byte)0xA2};

        IdpassConfig cfg = cls.getAnnotation(IdpassConfig.class);

        String strId = cfg.appletInstanceAID();
        byte[] id_bytes = Hex.decode(strId);
        currentSelected = cls.getCanonicalName();

        if (link == Link.SIM) {
            result = simulator.selectAppletWithResult(
                AIDUtil.create(id_bytes)); // @diff1_@
        } else if (link == Link.WIRED) {
            result = selectAppletWithResult(id_bytes); // @diff1@
        } else if (link == Link.WIRELESS) {
            // TODO:
        }
        byte[] sw = new byte[2];
        System.arraycopy(result, result.length - 2, sw, 0, sw.length);
        String s = String.format("SELECT %s ERROR", currentSelected);
        Assert.assertEquals(sw, Helper.SW9000, s);
        return result;
    }

    // This is the correct abstraction!
    public org.globalplatform.SecureChannel getSecureChannelInstance()
    {
        if (secureChannel == null) {
            // off-card side of SecureChannel
            secureChannel = new SCP02SecureChannel();
        }

        return secureChannel;
    }

    public ResponseAPDU Transmit(CommandAPDU apdu)
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

        } catch (CardException e) {
            e.printStackTrace();
        }
        return response;
    }

    public void init()
    {
        if (link == Link.SIM) {
            simulator.resetRuntime();
            install(DummyIssuerSecurityDomain.class);
            select(DummyIssuerSecurityDomain.class);
        } else if (link == Link.WIRED) {
            // TODO: delete all applets
            select(DummyIssuerSecurityDomain.class);
        }
    }

    public void initializeUpdate()
    {
        byte kvno = 0x00;
        initializeUpdate(kvno);
    }

    public void initializeUpdate(byte kvno)
    {
        SecureRandom random = new SecureRandom();
        random.nextBytes(_host_challenge);
        byte p1 = kvno;
        byte p2 = 0x00; // Must be always 0x00 GPCardSpec v2.3.1 E.5.1.4

        CommandAPDU command
            = new CommandAPDU(0x80, 0x50, p1, p2, _host_challenge);
        ResponseAPDU response;
        try {
            response = Transmit(command);
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
            Util.arrayCopyNonAtomic(cardresponse,
                                    (short)12,
                                    _card_challenge,
                                    (short)0,
                                    (byte)_card_challenge.length);
            // Save card_cryptogram
            Util.arrayCopyNonAtomic(cardresponse,
                                    (short)20,
                                    _card_cryptogram,
                                    (short)0,
                                    (byte)_card_cryptogram.length);

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
                this._bInitUpdated = true;
            }

            Assert.assertEquals(
                cgram, _card_cryptogram, "Cryptogram init-update offcard");

        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public void externalAuthenticate(byte securityLevel)
    {
        if (this._bInitUpdated == false) {
            throw new IllegalStateException(
                "Command failed: No SCP protocol found, need to run init-update first");
        }

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
            response = Transmit(command);
            Assert.assertEquals(
                0x9000, response.getSW(), "externalAuthenticate");
            if (response.getSW() == 0x9000) {
                this._securityLevel = securityLevel;
                this._bInitUpdated = false;
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    // This method is to appease mirror object instance so that
    // unification code is achieved between physical and simulator
    public AID installApplet(AID aid,
                             Class<? extends Applet> appletClass,
                             byte bArray[],
                             short bOffset,
                             byte bLength) throws SystemException
    {
        Method initMethod;

        try {
            initMethod = appletClass.getMethod(
                "install", new Class[] {byte[].class, short.class, byte.class});
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

        return aid;
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

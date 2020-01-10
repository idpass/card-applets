package org.idpass.offcard.proto;

import java.io.ByteArrayOutputStream;

import java.io.IOException;
import java.security.SecureRandom;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.proto.SCP02SecureChannel;

import org.idpass.offcard.applet.DummyIssuerSecurityDomain;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc._o;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

// import org.idpass.offcard.io.CardChannel;  // check this !!!

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.Util;

public class OffCard
{
    static private CardSimulator simulator = new CardSimulator();
    static private CardTerminal terminal
        = CardTerminalSimulator.terminal(simulator);
    static private Card card;
    static private CardChannel channel;

    static
    {
        try {
            card = terminal.connect("T=1");
            channel = card.getBasicChannel();
            sysInitialize();
        } catch (CardException e) {
            e.printStackTrace();
        }
    }

    static private Invariant Assert = new Invariant();

    static private byte[] kvno_prot = new byte[2];
    static private byte[] card_challenge = new byte[8];
    static private byte[] card_cryptogram = new byte[8];

    public static void ATR()
    {
        // This resets security level of previously selected applet
        select(DummyIssuerSecurityDomain.class);
    }

    public static void install(Class<? extends javacard.framework.Applet> cls)
    {
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
    }

    public static byte[] select(Class<? extends javacard.framework.Applet> cls)
    {
        byte[] result = {(byte)0x6A, (byte)0xA2};

        IdpassConfig cfg = cls.getAnnotation(IdpassConfig.class);

        String strId = cfg.appletInstanceAID();
        byte[] id_bytes = Hex.decode(strId);

        result = simulator.selectAppletWithResult(AIDUtil.create(id_bytes));

        return result;
    }

    public static ResponseAPDU Transmit(CommandAPDU apdu)
    {
        ResponseAPDU response = new ResponseAPDU(new byte[] {
            (byte)0x67,
            (byte)0x01,
        });

        try {
            response = channel.transmit(apdu);
        } catch (CardException e) {
            e.printStackTrace();
        }
        return response;
    }

    public static void sysInitialize()
    {
        simulator.resetRuntime();
        install(DummyIssuerSecurityDomain.class);
        select(DummyIssuerSecurityDomain.class);
    }

    public static byte[] select(AID aid)
    {
        byte[] result = simulator.selectAppletWithResult(aid);
        return result;
    }

    public static void initializeUpdate()
    {
        byte kvno = 0x00;
        initializeUpdate(kvno);
    }

    public static void initializeUpdate(byte kvno)
    {
        SecureRandom random = new SecureRandom();
        byte[] host_challenge = new byte[8];
        random.nextBytes(host_challenge);
        byte p1 = kvno;
        byte p2 = 0x00; // Must be always 0x00 GPCardSpec v2.1.1 E.5.1.4

        CommandAPDU command
            = new CommandAPDU(0x80, 0x50, p1, p2, host_challenge);
        ResponseAPDU response;
        try {
            response = channel.transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "initializeUpdate");
            byte[] cardresponse = response.getData();
            //_o.o_("initupdate response",cardresponse);

            // Save kvno_prot
            Util.arrayCopyNonAtomic(
                cardresponse, (short)10, kvno_prot, (short)0, (byte)2);
            // Save card_challenge!
            Util.arrayCopyNonAtomic(
                cardresponse, (short)12, card_challenge, (short)0, (byte)8);
            // Save card_cryptogram
            Util.arrayCopyNonAtomic(
                cardresponse, (short)20, card_cryptogram, (short)0, (byte)8);
        } catch (CardException e) {
            e.printStackTrace();
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public static void externalAuthenticate(byte securityLevel)
    {
        byte[] host_cryptogram
            = new byte[8]; // des_ede_cbc(resize8(sENC),nullbytes8,
                           // [card_challenge + host_challenge]);
        byte[] mac = new byte[8];

        // dummy values. TODO: Compute this
        host_cryptogram[0] = (byte)0xFA;
        host_cryptogram[1] = (byte)0xCE;
        mac[0] = (byte)0xBE;
        mac[1] = (byte)0xEF;

        byte p1 = securityLevel;
        byte p2 = 0x00; // Must be always 0x00 (GPCardspec v2.1.1 E.5.2.4)

        if ((p1 & SCP02SecureChannel.ENC) != 0) { // if ENC is set
            p1 = (byte)(p1 | SCP02SecureChannel.MAC); // then set MAC
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(host_cryptogram);
            bos.write(mac);
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] data = bos.toByteArray();

        CommandAPDU command = new CommandAPDU(0x84, 0x82, p1, p2, data);
        ResponseAPDU response;
        try {
            response = channel.transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(),
                              "externalAuthenticate");
        } catch (CardException e) {
            e.printStackTrace();
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }
}

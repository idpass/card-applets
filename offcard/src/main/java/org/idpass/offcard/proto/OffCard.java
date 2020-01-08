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

import org.idpass.offcard.applet.AuthApplet;
import org.idpass.offcard.applet.CafeBabeApplet;
import org.idpass.offcard.applet.DatastorageApplet;
import org.idpass.offcard.applet.SamApplet;

import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc._o;

// import org.idpass.offcard.io.CardChannel;  // check this !!!

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;

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

            simulator.installApplet(CafeBabeApplet.params.id_AID,
                                    CafeBabeApplet.class,
                                    CafeBabeApplet.params.getArray(),
                                    CafeBabeApplet.params.getOffset(),
                                    CafeBabeApplet.params.getLength());
            CafeBabeApplet.channel = channel;

        } catch (CardException e) {
            e.printStackTrace();
        }
    }

    static private Invariant Assert = new Invariant();

    static private byte[] kvno_prot = new byte[2];
    static private byte[] card_challenge = new byte[8];
    static private byte[] card_cryptogram = new byte[8];

    public static void install(Class<? extends javacard.framework.Applet> cls)
    {
        String appletClassName = cls.getCanonicalName();
        switch (appletClassName) {
        case "org.idpass.offcard.applet.AuthApplet":
            simulator.installApplet(AuthApplet.params.id_AID,
                                    AuthApplet.class,
                                    AuthApplet.params.getArray(),
                                    AuthApplet.params.getOffset(),
                                    AuthApplet.params.getLength());
            AuthApplet.channel = channel;
            break;

        case "org.idpass.offcard.applet.SamApplet":
            simulator.installApplet(SamApplet.params.id_AID,
                                    SamApplet.class,
                                    SamApplet.params.getArray(),
                                    SamApplet.params.getOffset(),
                                    SamApplet.params.getLength());
            SamApplet.channel = channel;
            break;

        case "org.idpass.offcard.applet.DatastorageApplet":
            simulator.installApplet(DatastorageApplet.params.id_AID,
                                    DatastorageApplet.class,
                                    DatastorageApplet.params.getArray(),
                                    DatastorageApplet.params.getOffset(),
                                    DatastorageApplet.params.getLength());
            DatastorageApplet.channel = channel;
            break;

        default:
            System.out.println("-- applet not found --");
            break;
        }
    }

    public static byte[] select(Class<? extends javacard.framework.Applet> cls)
    {
        byte[] result = {(byte)0x6A, (byte)0xA2};
        String appletClassName = cls.getCanonicalName();
        switch (appletClassName) {
        case "org.idpass.offcard.applet.AuthApplet":
            result = simulator.selectAppletWithResult(AuthApplet.params.id_AID);
            _o.o_("select retval AuthApplet", result);
            break;

        case "org.idpass.offcard.applet.SamApplet":
            result = simulator.selectAppletWithResult(SamApplet.params.id_AID);
            _o.o_("select retval SamApplet", result);
            break;

        case "org.idpass.offcard.applet.DatastorageApplet":
            result = simulator.selectAppletWithResult(
                DatastorageApplet.params.id_AID);
            _o.o_("select retval DatastorageApplet", result);
            break;

        default:
            System.out.println("-- applet not found --");
            break;
        }
        return result;
    }

    public static void initialize()
    {
        simulator.resetRuntime();
    }

    public static byte[] ATR()
    {
        // This resets security level of previously selected applet
        byte[] result
            = simulator.selectAppletWithResult(CafeBabeApplet.params.id_AID);
        return result;
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

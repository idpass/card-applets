package org.idpass.offcard.applet;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc.Params;
import org.idpass.offcard.misc._o;
import org.idpass.offcard.proto.SCP02SecureChannel;

public final class SamApplet extends org.idpass.sam.SamApplet
{
    private static String appletInstanceAID = "F76964706173730201000101";

    private static final byte[] privileges = {
        (byte)0xFF,
        (byte)0xFF,
    };

    private static final byte[] installParams = {
        (byte)0x42,
        (byte)0xFF,
    };

    public static Params params
        = new Params(appletInstanceAID, privileges, installParams);
    ///////////////////////////////////////////////////////////////////////////

    public static CardChannel channel; // this must not be null
    static private Invariant Assert = new Invariant();

    @Override public final boolean select()
    {
        secureChannel
            = new SCP02SecureChannel(); // GPSystem.getSecureChannel();
        return true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        SamApplet obj = new SamApplet(bArray, bOffset, bLength);
        obj.register(bArray, obj.aid_offset, obj.aid_len);
    }

    private SamApplet(byte[] bArray, short bOffset, byte bLength)
    {
        super(bArray, bOffset, bLength);
    }

    ///////////////////////////////////////////////////////////////////////////

    public static byte[] ENCRYPT(byte[] inData)
    {
        byte[] encryptedSigned = null;
        byte[] data = inData;
        CommandAPDU command
            = new CommandAPDU(/*0x00*/ 0x04, 0xEC, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = channel.transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "ENCRYPT");
            if (0x9000 == response.getSW()) {
                encryptedSigned = response.getData();
                _o.o_("Encrypted by SamApplet", encryptedSigned);
            }
        } catch (CardException e) {
            e.printStackTrace();
        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return encryptedSigned;
    }

    public static byte[] DECRYPT(byte[] outData)
    {
        byte[] decryptedData = null;
        byte[] data = outData;
        CommandAPDU command
            = new CommandAPDU(/*0x00*/ 0x04, 0xDC, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = channel.transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "DECRYPT");
            if (0x9000 == response.getSW()) {
                decryptedData = response.getData();
                _o.o_("Decrypted by SamApplet", decryptedData);
            }
        } catch (CardException e) {
            e.printStackTrace();
        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return decryptedData;
    }
}

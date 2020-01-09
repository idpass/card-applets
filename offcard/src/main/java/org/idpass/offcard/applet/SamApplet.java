package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc.Params;
import org.idpass.offcard.misc._o;
import org.idpass.offcard.proto.SCP02SecureChannel;
import org.idpass.offcard.proto.ICardConnection;

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

    public static ICardConnection connection;
    static private Invariant Assert = new Invariant();

    @Override public final boolean select()
    {
        secureChannel = new SCP02SecureChannel();
        return true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        SamApplet obj = new SamApplet(bArray, bOffset, bLength, retval);

        short aid_offset = ByteBuffer.wrap(retval, 0, 2)
                               .order(ByteOrder.BIG_ENDIAN)
                               .getShort();
        byte aid_len = retval[2];
        obj.register(bArray, aid_offset, aid_len);
    }

    private SamApplet(byte[] bArray, short bOffset, byte bLength, byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
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
            response = connection.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "ENCRYPT");
            if (0x9000 == response.getSW()) {
                encryptedSigned = response.getData();
                _o.o_("Encrypted by SamApplet", encryptedSigned);
            }
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
            response = connection.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "DECRYPT");
            if (0x9000 == response.getSW()) {
                decryptedData = response.getData();
                _o.o_("Decrypted by SamApplet", decryptedData);
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return decryptedData;
    }
}

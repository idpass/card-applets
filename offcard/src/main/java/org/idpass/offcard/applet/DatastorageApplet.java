package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc.Params;
import org.idpass.offcard.proto.SCP02SecureChannel;

public final class DatastorageApplet
    extends org.idpass.datastorage.DatastorageApplet
{
    private static String appletInstanceAID = "F76964706173730301000101";

    private static final byte[] privileges = {
        (byte)0xFF,
        (byte)0xFF,
    };

    private static final byte[] installParams = {
        (byte)0x42,
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
        DatastorageApplet obj = new DatastorageApplet(bArray, bOffset, bLength);
        obj.register(bArray, obj.aid_offset, obj.aid_len);
    }

    private DatastorageApplet(byte[] bArray, short bOffset, byte bLength)
    {
        super(bArray, bOffset, bLength);
    }
    ///////////////////////////////////////////////////////////////////////////

    public static short SWITCH()
    {
        short vcardId = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x9C, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = channel.transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "SWITCH");
            if (0x9000 == response.getSW()) {
                vcardId = ByteBuffer.wrap(response.getData())
                              .order(ByteOrder.BIG_ENDIAN)
                              .getShort();
                System.out.println(String.format("vcardId = 0x%04X", vcardId));
            }
        } catch (CardException e) {
            e.printStackTrace();
        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return vcardId;
    }
}

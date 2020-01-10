package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.proto.OffCard;
import org.idpass.offcard.proto.SCP02SecureChannel;

@IdpassConfig(
    appletInstanceAID = "DEC0DE0000",
    installParams = {
        (byte)0x42
    },
    privileges = {
        (byte)0xFF,
        (byte)0xFF,
    })
public class DecodeApplet extends org.idpass.dev.DecodeApplet
{
    static private Invariant Assert = new Invariant();
    ////////////////////////////////////////////////////////////////////////////
    @Override public final boolean select()
    {
        secureChannel = new SCP02SecureChannel();
        return true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        DecodeApplet obj = new DecodeApplet(bArray, bOffset, bLength, retval);

        short aid_offset = ByteBuffer.wrap(retval, 0, 2)
                               .order(ByteOrder.BIG_ENDIAN)
                               .getShort();
        byte aid_len = retval[2];
        obj.register(bArray, aid_offset, aid_len);
    }

    private DecodeApplet(byte[] bArray,
                         short bOffset,
                         byte bLength,
                         byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
    }
    ////////////////////////////////////////////////////////////////////////////
    public static void ins_noop()
    {
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x00, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "ins_noop");
            if (0x9000 == response.getSW()) {

            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public static void ins_echo()
    {
        short newPersonaIndex = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x01, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "ins_echo");
            if (0x9000 == response.getSW()) {
                newPersonaIndex = ByteBuffer.wrap(response.getData())
                                      .order(ByteOrder.BIG_ENDIAN)
                                      .getShort();
                System.out.println(
                    String.format("retval = 0x%04X", newPersonaIndex));
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public static void ins_control()
    {
        short newPersonaIndex = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x02, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "ins_control");
            if (0x9000 == response.getSW()) {
                newPersonaIndex = ByteBuffer.wrap(response.getData())
                                      .order(ByteOrder.BIG_ENDIAN)
                                      .getShort();
                System.out.println(
                    String.format("retval = 0x%04X", newPersonaIndex));
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }
}

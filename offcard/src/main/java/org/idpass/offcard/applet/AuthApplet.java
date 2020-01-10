package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc._o;
import org.idpass.offcard.proto.SCP02SecureChannel;
import org.idpass.offcard.proto.OffCard;

@IdpassConfig(
    appletInstanceAID = "F76964706173730101000101",
    installParams = {
        (byte)0x00,
        (byte)0x05,
        (byte)0x42,
    },
    privileges = { 
        (byte)0xFF,
        (byte)0xFF,
    })
public final class AuthApplet extends org.idpass.auth.AuthApplet
{
    static private Invariant Assert = new Invariant();

    @Override public final boolean select()
    {
        secureChannel = new SCP02SecureChannel();
        return true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        AuthApplet obj = new AuthApplet(bArray, bOffset, bLength, retval);

        short aid_offset = ByteBuffer.wrap(retval, 0, 2)
                               .order(ByteOrder.BIG_ENDIAN)
                               .getShort();
        byte aid_len = retval[2];
        obj.register(bArray, aid_offset, aid_len);
    }

    private AuthApplet(byte[] bArray,
                       short bOffset,
                       byte bLength,
                       byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
    }

    ////////////////////////////////////////////////////////////////////////////
    // processAddPersona
    public static short AP()
    {
        short newPersonaIndex = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x1A, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "AP");
            if (0x9000 == response.getSW()) {
                newPersonaIndex = ByteBuffer.wrap(response.getData())
                                      .order(ByteOrder.BIG_ENDIAN)
                                      .getShort();
                System.out.println(
                    String.format("AP retval = 0x%04X", newPersonaIndex));
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return newPersonaIndex;
    }

    // processDeletePersona
    public static void DP(byte personaIndex)
    {
        byte p2 = personaIndex;
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x1D, 0x00, p2);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "DP");
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    // processAddListener
    public static short AL(byte[] listener)
    {
        short newListenerIndex = (short)0xFFFF;
        byte[] data = listener;
        CommandAPDU command
            = new CommandAPDU(/*0x00*/ 0x04, 0xAA, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "AL");
            if (0x9000 == response.getSW()) {
                newListenerIndex = ByteBuffer.wrap(response.getData())
                                       .order(ByteOrder.BIG_ENDIAN)
                                       .getShort();
                System.out.println(
                    String.format("AL retval = 0x%04X", newListenerIndex));
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }

        return newListenerIndex;
    }

    // processDeleteListener
    public static boolean DL(byte[] listener)
    {
        byte[] status = null;
        byte[] data = listener;
        CommandAPDU command
            = new CommandAPDU(/*0x00*/ 0x04, 0xDA, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "DL");
            if (0x9000 == response.getSW()) {
                status = response.getData();
                _o.o_("DL retval", status);
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return status != null && status[0] == 0x01;
    }

    // processAddVerifierForPersona
    public static short AVP(byte personaId, byte[] authData)
    {
        short newVerifierIndex = (short)0xFFFF;
        byte[] data = authData;
        byte p2 = personaId;
        CommandAPDU command
            = new CommandAPDU(/*0x00*/ 0x04, 0x2A, 0x00, p2, data);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "AVP");
            if (0x9000 == response.getSW()) {
                newVerifierIndex = ByteBuffer.wrap(response.getData())
                                       .order(ByteOrder.BIG_ENDIAN)
                                       .getShort();
                System.out.println(
                    String.format("AVP retval = 0x%04X", newVerifierIndex));
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }

        return newVerifierIndex;
    }

    // processDeleteVerifierFromPersona
    public static void DVP(byte personaIndex, byte verifierIndex)
    {
        byte p1 = personaIndex;
        byte p2 = verifierIndex;
        CommandAPDU command
            = new CommandAPDU(/*0x00*/ 0x04, 0x2D, 0x00, p1, p2);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "DVP");
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    // processAuthenticatePersona
    public static int AUP(byte[] authData)
    {
        int indexScore = 0xFFFFFFFF;
        byte[] data = authData;
        CommandAPDU command
            = new CommandAPDU(/*0x00*/ 0x04, 0xEF, 0x1D, 0xCD, data);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "AUP");
            if (0x9000 == response.getSW()) {
                indexScore = ByteBuffer.wrap(response.getData())
                                 .order(ByteOrder.BIG_ENDIAN)
                                 .getInt();
                System.out.println(
                    String.format("AUP retval = 0x%08X", indexScore));
            }

        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return indexScore;
    }
}

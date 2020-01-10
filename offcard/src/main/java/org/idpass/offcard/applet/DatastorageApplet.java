package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.proto.SCP02SecureChannel;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import org.idpass.offcard.proto.OffCard;

@IdpassConfig(
    appletInstanceAID = "F76964706173730301000101",
    installParams = {
        (byte)0x42,
    },
    privileges = {
        (byte)0xFF,
        (byte)0xFF,
    })
public final class DatastorageApplet
    extends org.idpass.datastorage.DatastorageApplet
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
        DatastorageApplet obj
            = new DatastorageApplet(bArray, bOffset, bLength, retval);

        short aid_offset = ByteBuffer.wrap(retval, 0, 2)
                               .order(ByteOrder.BIG_ENDIAN)
                               .getShort();
        byte aid_len = retval[2];
        obj.register(bArray, aid_offset, aid_len);
    }

    private DatastorageApplet(byte[] bArray,
                              short bOffset,
                              byte bLength,
                              byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
    }
    
    public static byte[] id_bytes()
    {
        byte[] instanceAID = null;

        IdpassConfig cfg = DatastorageApplet.class.getAnnotation(IdpassConfig.class);
        String strId = cfg.appletInstanceAID();
        byte[] id_bytes = Hex.decode(strId);
        instanceAID = id_bytes; 
        
        return instanceAID;
    }
    
    ///////////////////////////////////////////////////////////////////////////

    public static short SWITCH()
    {
        short vcardId = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x9C, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW(), "SWITCH");
            if (0x9000 == response.getSW()) {
                vcardId = ByteBuffer.wrap(response.getData())
                              .order(ByteOrder.BIG_ENDIAN)
                              .getShort();
                System.out.println(String.format("vcardId = 0x%04X", vcardId));
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return vcardId;
    }

    public static byte[] GET_APPLICATION_IDS()
    {
        byte[] retval = null;
        CommandAPDU command = new CommandAPDU(0x00, 0x6A, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW()
                                  || 0x9100 == response.getSW(),
                              "GET_APPLICATION_IDS");
            if (0x9000 == response.getSW()) {
                retval = response.getData();
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }

        return retval;
    }

    public static void CREATE_APPLICATION(byte[] app)
    {
        byte[] data = app;
        CommandAPDU command = new CommandAPDU(0x00, 0xCA, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9100 == response.getSW(), "CREATE_APPLICATION");
            if (0x9100 == response.getSW()) {
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public static void DELETE_APPLICATION(byte[] id)
    {
        byte[] data = id;
        CommandAPDU command = new CommandAPDU(0x00, 0xDA, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = OffCard.Transmit(command);
            Assert.assertTrue(0x9100 == response.getSW(), "DELETE_APPLICATION");
            if (0x9100 == response.getSW()) {
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }
}

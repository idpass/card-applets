package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc._o;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.SystemException;
import javacard.framework.Util;

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
    private static byte[] id_bytes;
    private static Invariant Assert = new Invariant();
    private static DatastorageApplet instance;

    public static DatastorageApplet getInstance()
    {
        return instance;
    }

    @Override public final boolean select()
    {
        if (secureChannel == null) {
            secureChannel = OffCard.getInstance().getSecureChannelInstance();
        }

        return true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        DatastorageApplet obj
            = new DatastorageApplet(bArray, bOffset, bLength, retval);

        short aid_offset = Util.makeShort(retval[0], retval[1]);
        byte aid_len = retval[2];
        try {
            obj.register(bArray, aid_offset, aid_len);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "DatastorageApplet::install");
        }
        instance = obj;
    }

    private DatastorageApplet(byte[] bArray,
                              short bOffset,
                              byte bLength,
                              byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
    }

    public byte[] instanceAID()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = DatastorageApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.appletInstanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }

    @Override public void onPersonaAdded(short personaIndex)
    {
        super.onPersonaAdded(personaIndex);
        System.out.println("DatastorageApplet::onPersonaAdded");
    }

    @Override public void onPersonaDeleted(short personaIndex)
    {
        super.onPersonaDeleted(personaIndex);
        System.out.println("DatastorageApplet::onPersonaDeleted");
    }

    @Override
    public void onPersonaAuthenticated(short personaIndex, short score)
    {
        super.onPersonaAuthenticated(personaIndex, score);
        System.out.println("DatastorageApplet::onPersonaAuthenticated");
    }

    ///////////////////////////////////////////////////////////////////////////

    public short SWITCH()
    {
        short vcardId = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x9C, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "SWITCH");
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

    public byte[] GET_APPLICATION_IDS()
    {
        byte[] retval = null;
        CommandAPDU command = new CommandAPDU(0x00, 0x6A, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertTrue(0x9000 == response.getSW()
                                  || 0x9100 == response.getSW(),
                              "GET_APPLICATION_IDS");
            if (0x9000 == response.getSW()) {
                retval = response.getData();
                _o.o_("APPLICATION_IDS", retval);
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }

        return retval;
    }

    public void CREATE_APPLICATION(byte[] app)
    {
        byte[] data = app;
        CommandAPDU command = new CommandAPDU(0x00, 0xCA, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertEquals(0x9100, response.getSW(), "CREATE_APPLICATION");
            if (0x9100 == response.getSW()) {
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public void DELETE_APPLICATION(byte[] id)
    {
        byte[] data = id;
        CommandAPDU command = new CommandAPDU(0x00, 0xDA, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertEquals(0x9100, response.getSW(), "DELETE_APPLICATION");
            if (0x9100 == response.getSW()) {
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }
}

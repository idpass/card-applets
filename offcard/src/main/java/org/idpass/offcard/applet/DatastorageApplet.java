package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc.Dump;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.SystemException;

import org.idpass.offcard.proto.OffCard;

@IdpassConfig(
    packageAID  = "F769647061737303",
    appletAID   = "F769647061737303010001",
    instanceAID = "F76964706173730301000101",
    capFile = "datastorage.cap",
    installParams = {
        (byte)0x9E,
    },
    privileges = {
        (byte)0xFF,
        (byte)0xFF,
    }
)
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

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        DatastorageApplet applet
            = new DatastorageApplet(bArray, bOffset, bLength);

        try {
            applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "DatastorageApplet::install");
        }
        instance = applet;
    }

    @Override public final boolean select()
    {
        if (secureChannel == null) {
            secureChannel = DummyISDApplet.getInstance().getSecureChannel();
        }

        return true;
    }

    public byte[] SELECT()
    {
        return OffCard.getInstance().select(DatastorageApplet.class);
    }

    private DatastorageApplet(byte[] bArray, short bOffset, byte bLength)
    {
        super(bArray, bOffset, bLength);
    }

    public byte[] aid()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = DatastorageApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.instanceAID();
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

    public short processSwitchNextVirtualCard()
    {
        short vcardId = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(0x00, 0x9C, 0x00, 0x00);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            vcardId = ByteBuffer.wrap(response.getData())
                          .order(ByteOrder.BIG_ENDIAN)
                          .getShort();
            System.out.println(String.format("vcardId = 0x%04X", vcardId));
        }
        return vcardId;
    }

    public byte[] GET_APPLICATION_IDS()
    {
        byte[] retval = null;
        CommandAPDU command = new CommandAPDU(0x00, 0x6A, 0x00, 0x00);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        /*
        Assert.assertTrue(0x9000 == response.getSW()
                              || 0x9100 == response.getSW(),
                          "GET_APPLICATION_IDS");*/
        if (0x9000 == response.getSW()) {
            retval = response.getData();
            Dump.print("APPLICATION_IDS", retval);
        }

        return retval;
    }

    public void CREATE_APPLICATION(byte[] app)
    {
        byte[] data = app;
        CommandAPDU command = new CommandAPDU(0x00, 0xCA, 0x00, 0x00, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9100 == response.getSW()) {
            System.out.println("CREATE_APPLICATION ok");
        }
    }

    public void DELETE_APPLICATION(byte[] id)
    {
        byte[] data = id;
        CommandAPDU command = new CommandAPDU(0x00, 0xDA, 0x00, 0x00, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        if (0x9100 == response.getSW()) {
            System.out.println("DELETE_APPLICATION");
        }
    }
}

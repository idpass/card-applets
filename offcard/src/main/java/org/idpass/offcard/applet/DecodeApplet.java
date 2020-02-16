package org.idpass.offcard.applet;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.proto.OffCard;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.SystemException;

@IdpassConfig(
    packageAID  = "DEC0DE0000",
    appletAID   = "DEC0DE000001",
    instanceAID = "DEC0DE00000101",
    capFile = "decode.cap",
    installParams = {
        (byte)0x00
    },
    privileges = {
        (byte)0xFF,
        (byte)0xFF,
    }
)
public class DecodeApplet extends org.idpass.dev.DecodeApplet
{
    private static byte[] id_bytes;
    private static Invariant Assert = new Invariant();
    private static DecodeApplet instance;

    public static DecodeApplet getInstance()
    {
        return instance;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        DecodeApplet applet = new DecodeApplet(bArray, bOffset, bLength);

        try {
            applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "DecodeApplet::install");
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
        return OffCard.getInstance().select(DecodeApplet.class);
    }

    private DecodeApplet(byte[] bArray, short bOffset, byte bLength)
    {
        super(bArray, bOffset, bLength);
    }

    public byte[] aid()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = DecodeApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.instanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }
    ////////////////////////////////////////////////////////////////////////////
    public void ins_noop(byte[] data)
    {
        CommandAPDU command = null;

        if (data != null && data.length > 0) {
            command = new CommandAPDU(0x00, 0x00, 0x00, 0x00, data);
        } else {
            command = new CommandAPDU(0x00, 0x00, 0x00, 0x00);
        }

        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
        }
    }

    public byte[] ins_echo(byte[] input, int p1, int p2)
    {
        byte[] data = {};
        CommandAPDU command
            = new CommandAPDU(0x00, 0x01, (byte)p1, (byte)p2, input);
        ResponseAPDU response;

        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            data = response.getData();
            if (data.length > 0) {

            }
        }

        return data;
    }

    public void ins_control(int p1)
    {
        CommandAPDU command = new CommandAPDU(0x00, 0x02, p1, 0x00);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
        }
    }
}

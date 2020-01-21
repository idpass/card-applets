package org.idpass.offcard.applet;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc._o;
import org.idpass.offcard.proto.OffCard;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.SystemException;
import javacard.framework.Util;

@IdpassConfig(
    appletInstanceAID = "DEC0DE000001",
    installParams = {
        (byte)0x00
    },
    privileges = {
        (byte)0xFF,
        (byte)0xFF,
    })
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
        byte[] retval = new byte[4];
        instance = new DecodeApplet(bArray, bOffset, bLength, retval);

        short aid_offset = Util.makeShort(retval[0], retval[1]);
        byte aid_len = retval[2];
        try {
            instance.register(bArray, aid_offset, aid_len);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "DecodeApplet::install");
        }
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

    private DecodeApplet(byte[] bArray,
                         short bOffset,
                         byte bLength,
                         byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
    }

    public byte[] aid()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = DecodeApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.appletInstanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }
    ////////////////////////////////////////////////////////////////////////////
    public void ins_noop()
    {
        byte[] data;
        CommandAPDU command = new CommandAPDU(0x00, 0x00, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "ins_noop");
            if (0x9000 == response.getSW()) {
                data = response.getData();
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public byte[] ins_echo(byte[] input, int p1, int p2)
    {
        System.out.println(input.length);
        byte[] data = {};
        CommandAPDU command
            = new CommandAPDU(0x00, 0x01, (byte)p1, (byte)p2, input);
        ResponseAPDU response;

        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "ins_echo");
            if (0x9000 == response.getSW()) {
                data = response.getData();
                if (data.length > 0) {
                    _o.o_(data, "ins_echo");
                }
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }

        return data;
    }

    public void ins_control(int p1)
    {
        CommandAPDU command = new CommandAPDU(0x00, 0x02, p1, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "ins_control");
            if (0x9000 == response.getSW()) {
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }
}

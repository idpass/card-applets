package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
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

    @Override public final boolean select()
    {
        if (secureChannel == null) {
            secureChannel
                = DummyIssuerSecurityDomain.GPSystem_getSecureChannel();
        }

        return true;
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

    private DecodeApplet(byte[] bArray,
                         short bOffset,
                         byte bLength,
                         byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
    }

    public byte[] id_bytes()
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
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x00, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "ins_noop");
            if (0x9000 == response.getSW()) {
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
    }

    public void ins_echo()
    {
        short newPersonaIndex = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x01, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "ins_echo");
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

    public void ins_control()
    {
        short newPersonaIndex = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(/*0x00*/ 0x04, 0x02, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = OffCard.getInstance().Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "ins_control");
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

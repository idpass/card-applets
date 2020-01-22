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
    appletInstanceAID = "F76964706173730101000101",
    installParams = {
        (byte) 0x00,    // simple pin byte array
        // (byte) 0x03  // javacardx.biometry.BioBuilder
        (byte)0x05,
        (byte)0x42,
    },
    privileges = { 
        (byte)0xFF,
        (byte)0xFF,
    }
)
public class AuthApplet extends org.idpass.auth.AuthApplet
{
    private static byte[] id_bytes;
    private static Invariant Assert = new Invariant();
    private static AuthApplet instance;

    public static AuthApplet getInstance()
    {
        return instance;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        AuthApplet obj = new AuthApplet(bArray, bOffset, bLength, retval);

        short aid_offset = Util.makeShort(retval[0], retval[1]);
        byte aid_len = retval[2];
        try {
            obj.register(bArray, aid_offset, aid_len);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "AuthApplet::install");
        }
        instance = obj;
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
        return OffCard.getInstance().select(AuthApplet.class);
    }

    private AuthApplet(byte[] bArray,
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
                = AuthApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.appletInstanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }
    ////////////////////////////////////////////////////////////////////////////
    // processAddPersona
    public short processAddPersona()
    {
        short newPersonaIndex = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(0x00, 0x1A, 0x00, 0x00);
        ResponseAPDU response;

        response = OffCard.getInstance().Transmit(command);
        Assert.assertEquals(0x9000, response.getSW(), "AP");
        if (0x9000 == response.getSW()) {
            newPersonaIndex = ByteBuffer.wrap(response.getData())
                                  .order(ByteOrder.BIG_ENDIAN)
                                  .getShort();
            System.out.println(
                String.format("AP retval = 0x%04X", newPersonaIndex));
        }

        return newPersonaIndex;
    }

    // processDeletePersona
    public void processDeletePersona(byte personaIndex)
    {
        byte p2 = personaIndex;
        CommandAPDU command = new CommandAPDU(0x00, 0x1D, 0x00, p2);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        Assert.assertEquals(0x9000, response.getSW(), "DP");
    }

    // processAddListener
    public short processAddListener(byte[] listener)
    {
        short newListenerIndex = (short)0xFFFF;
        byte[] data = listener;
        CommandAPDU command = new CommandAPDU(0x00, 0xAA, 0x00, 0x00, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        Assert.assertEquals(0x9000, response.getSW(), "AL");
        if (0x9000 == response.getSW()) {
            newListenerIndex = ByteBuffer.wrap(response.getData())
                                   .order(ByteOrder.BIG_ENDIAN)
                                   .getShort();
            System.out.println(
                String.format("AL retval = 0x%04X", newListenerIndex));
        }
        return newListenerIndex;
    }

    // processDeleteListener
    public boolean processDeleteListener(byte[] listener)
    {
        byte[] status = null;
        byte[] data = listener;
        CommandAPDU command = new CommandAPDU(0x00, 0xDA, 0x00, 0x00, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        Assert.assertEquals(0x9000, response.getSW(), "DL");
        if (0x9000 == response.getSW()) {
            status = response.getData();
            _o.o_("DL retval", status);
        }
        return status != null && status[0] == 0x01;
    }

    // processAddVerifierForPersona
    public short processAddVerifierForPersona(byte personaId, byte[] authData)
    {
        short newVerifierIndex = (short)0xFFFF;
        byte[] data = authData;
        byte p2 = personaId;
        CommandAPDU command = new CommandAPDU(0x00, 0x2A, 0x00, p2, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        Assert.assertEquals(0x9000, response.getSW(), "AVP");
        if (0x9000 == response.getSW()) {
            newVerifierIndex = ByteBuffer.wrap(response.getData())
                                   .order(ByteOrder.BIG_ENDIAN)
                                   .getShort();
            System.out.println(
                String.format("AVP retval = 0x%04X", newVerifierIndex));
        }
        return newVerifierIndex;
    }

    // processDeleteVerifierFromPersona
    public void processDeleteVerifierFromPersona(byte personaIndex,
                                                 byte verifierIndex)
    {
        byte p1 = personaIndex;
        byte p2 = verifierIndex;
        CommandAPDU command = new CommandAPDU(0x00, 0x2D, 0x00, p1, p2);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        Assert.assertEquals(0x9000, response.getSW(), "DVP");
    }

    // processAuthenticatePersona
    public int processAuthenticatePersona(byte[] authData)
    {
        int indexScore = 0xFFFFFFFF;
        byte[] data = authData;
        CommandAPDU command = new CommandAPDU(0x00, 0xEF, 0x1D, 0xCD, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        Assert.assertEquals(0x9000, response.getSW(), "AUP");
        if (0x9000 == response.getSW()) {
            indexScore = ByteBuffer.wrap(response.getData())
                             .order(ByteOrder.BIG_ENDIAN)
                             .getInt();
            System.out.println(
                String.format("AUP retval = 0x%08X", indexScore));
        }

        return indexScore;
    }
}

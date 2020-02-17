package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.SystemException;

import org.idpass.offcard.proto.OffCard;

@IdpassConfig(
    packageAID  = "F769647061737301",
    appletAID   = "F769647061737301010001",
    instanceAID = "F76964706173730101000101",
    capFile = "auth.cap",
    installParams = {
        (byte)0x00, // PIN = 0x00, FINGERPRINT = 0x03
        (byte)0x01,
        (byte)0x9E,
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
        AuthApplet applet = new AuthApplet(bArray, bOffset, bLength);

        try {
            applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "AuthApplet::install");
        }
        instance = applet;
    }

    @Override public final boolean select()
    {
        if (secureChannel == null) {
            secureChannel = DummyISDApplet.getInstance().getSecureChannel();
        }
        secureChannel.resetSecurity();
        return true;
    }

    public byte[] SELECT()
    {
        return OffCard.getInstance().select(AuthApplet.class);
    }

    private AuthApplet(byte[] bArray, short bOffset, byte bLength)
    {
        super(bArray, bOffset, bLength);
    }

    public byte[] aid()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = AuthApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.instanceAID();
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
        if (0x9000 == response.getSW()) {
            newPersonaIndex = ByteBuffer.wrap(response.getData())
                                  .order(ByteOrder.BIG_ENDIAN)
                                  .getShort();
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
        if (response.getSW() == 0x9000) {

        }
    }

    // processAddListener
    public short processAddListener(byte[] listener)
    {
        short newListenerIndex = (short)0xFFFF;
        byte[] data = listener;
        CommandAPDU command = new CommandAPDU(0x00, 0xAA, 0x00, 0x00, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            newListenerIndex = ByteBuffer.wrap(response.getData())
                                   .order(ByteOrder.BIG_ENDIAN)
                                   .getShort();
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

        if (0x9000 == response.getSW()) {
            status = response.getData();
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

        if (0x9000 == response.getSW()) {
            newVerifierIndex = ByteBuffer.wrap(response.getData())
                                   .order(ByteOrder.BIG_ENDIAN)
                                   .getShort();
        }
        return newVerifierIndex;
    }

    // processDeleteVerifierFromPersona
    public void processDeleteVerifierFromPersona(byte personaIndex,
                                                 byte verifierIndex)
    {
        byte p1 = personaIndex;
        byte p2 = verifierIndex;
        CommandAPDU command = new CommandAPDU(0x00, 0x2D, p1, p2);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        if (response.getSW() == 0x9000) {

        }
    }

    // processAuthenticatePersona
    public int processAuthenticatePersona(byte[] authData)
    {
        int indexScore = 0xFFFFFFFF;
        byte[] data = authData;
        CommandAPDU command = new CommandAPDU(0x00, 0xEF, 0x1D, 0xCD, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            indexScore = ByteBuffer.wrap(response.getData())
                             .order(ByteOrder.BIG_ENDIAN)
                             .getInt();
        }

        return indexScore;
    }
}

package org.idpass.offcard.applet;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.SystemException;

import org.idpass.offcard.proto.OffCard;

@IdpassConfig(
    packageAID  = "F769647061737302",
    appletAID   = "F769647061737302010001",
    instanceAID = "F76964706173730201000101",
    capFile = "sam.cap",
    installParams = {
        (byte)0x9E,
    },
    privileges = {
        (byte)0xFF,
        (byte)0xFF,
    }
)
public final class SamApplet extends org.idpass.sam.SamApplet
{
    private static byte[] id_bytes;
    private static Invariant Assert = new Invariant();
    private static SamApplet instance;

    public static SamApplet getInstance()
    {
        return instance;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        SamApplet applet = new SamApplet(bArray, bOffset, bLength);

        try {
            applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "SamApplet::install");
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
        return OffCard.getInstance().select(SamApplet.class);
    }

    private SamApplet(byte[] bArray, short bOffset, byte bLength)
    {
        super(bArray, bOffset, bLength);
    }

    public byte[] aid()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = SamApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.instanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }

    @Override public void onPersonaAdded(short personaIndex)
    {
        super.onPersonaAdded(personaIndex);
    }

    @Override public void onPersonaDeleted(short personaIndex)
    {
        super.onPersonaDeleted(personaIndex);
    }

    @Override
    public void onPersonaAuthenticated(short personaIndex, short score)
    {
        super.onPersonaAuthenticated(personaIndex, score);
    }
    ///////////////////////////////////////////////////////////////////////////

    public byte[] processEncrypt(byte[] inData)
    {
        byte[] encryptedSigned = null;
        byte[] data = inData;
        CommandAPDU command = new CommandAPDU(0x00, 0xEC, 0x00, 0x00, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            encryptedSigned = response.getData();
        }
        return encryptedSigned;
    }

    public byte[] processDecrypt(byte[] outData)
    {
        byte[] decryptedData = null;
        byte[] data = outData;
        CommandAPDU command = new CommandAPDU(0x00, 0xDC, 0x00, 0x00, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            decryptedData = response.getData();
        }
        return decryptedData;
    }
}

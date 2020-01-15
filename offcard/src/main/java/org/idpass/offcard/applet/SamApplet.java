package org.idpass.offcard.applet;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.interfaces.ISamApplet;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc._o;
import org.idpass.offcard.proto.SCP02SecureChannel;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.Util;

import org.idpass.offcard.proto.OffCard;

@IdpassConfig(
    appletInstanceAID = "F76964706173730201000101",
    installParams = {
        (byte)0x42,
    },
    privileges = {
        (byte)0xFF,
        (byte)0xFF,
    })
public final class SamApplet extends org.idpass.sam.SamApplet implements ISamApplet
{
    private static byte[] id_bytes;
    private static Invariant Assert = new Invariant();
    private static ISamApplet instance;
    private OffCard offcard = OffCard.getInstance();

    public static ISamApplet getInstance()
    {
        if (instance == null) {
            System.out.println("-- incarnate real object here --");
            instance = new org.idpass.offcard.phys.SamApplet();
        }

        return instance;
    }

    @Override public final boolean select()
    {
        if (secureChannel == null) {
            secureChannel = offcard.getSecureChannelInterface();
        }
        return true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        SamApplet obj = new SamApplet(bArray, bOffset, bLength, retval);

        short aid_offset = Util.makeShort(retval[0], retval[1]);
        byte aid_len = retval[2];
        obj.register(bArray, aid_offset, aid_len);
        instance = obj;
    }

    private SamApplet(byte[] bArray, short bOffset, byte bLength, byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
    }

    @Override public byte[] instanceAID()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = SamApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.appletInstanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }

    @Override public void onPersonaAdded(short personaIndex)
    {
        super.onPersonaAdded(personaIndex);
        System.out.println("SamApplet::onPersonaAdded");
    }

    @Override public void onPersonaDeleted(short personaIndex)
    {
        super.onPersonaDeleted(personaIndex);
        System.out.println("SamApplet::onPersonaDeleted");
    }

    @Override
    public void onPersonaAuthenticated(short personaIndex, short score)
    {
        super.onPersonaAuthenticated(personaIndex, score);
        System.out.println("SamApplet::onPersonaAuthenticated");
    }
    ///////////////////////////////////////////////////////////////////////////

    @Override public byte[] ENCRYPT(byte[] inData)
    {
        byte[] encryptedSigned = null;
        byte[] data = inData;
        CommandAPDU command
            = new CommandAPDU(/*0x00*/ 0x04, 0xEC, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = offcard.Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "ENCRYPT");
            if (0x9000 == response.getSW()) {
                encryptedSigned = response.getData();
                _o.o_("Encrypted by SamApplet", encryptedSigned);
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return encryptedSigned;
    }

    @Override public byte[] DECRYPT(byte[] outData)
    {
        byte[] decryptedData = null;
        byte[] data = outData;
        CommandAPDU command
            = new CommandAPDU(/*0x00*/ 0x04, 0xDC, 0x00, 0x00, data);
        ResponseAPDU response;
        try {
            response = offcard.Transmit(command);
            Assert.assertEquals(0x9000, response.getSW(), "DECRYPT");
            if (0x9000 == response.getSW()) {
                decryptedData = response.getData();
                _o.o_("Decrypted by SamApplet", decryptedData);
            }
        } catch (AssertionError e) {
            e.printStackTrace();
        }
        return decryptedData;
    }
}

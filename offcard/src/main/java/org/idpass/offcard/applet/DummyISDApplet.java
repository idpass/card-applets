package org.idpass.offcard.applet;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.proto.OffCard;
import org.idpass.offcard.proto.SCP02Keys;
import org.idpass.offcard.proto.SCP02;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.Util;

@IdpassConfig(
    //instanceAID = "A0000001510000",
    instanceAID = "D1560001320D0101",
    installParams = {
        (byte)0x42
    },
    privileges = {
        (byte)0xFF,
        (byte)0xFF,
    }
)
public class DummyISDApplet extends Applet
{
    // clang-format off
    // Keys inside the card
    private static SCP02Keys cardKeys[] = {
        new SCP02Keys("404142434445464748494a4b4c4d4e4F", // 1
                      "404142434445464748494a4b4c4d4e4F",
                      "404142434445464748494a4b4c4d4e4F"),

        new SCP02Keys("DEC0DE0102030405060708090A0B0C0D", // 2
                      "DEC0DE0102030405060708090A0B0C0D",
                      "DEC0DE0102030405060708090A0B0C0D"),

        new SCP02Keys("CAFEBABE0102030405060708090A0B0C", // 3
                      "CAFEBABE0102030405060708090A0B0C",
                      "CAFEBABE0102030405060708090A0B0C"),

        new SCP02Keys("C0FFEE0102030405060708090A0B0C0D", // 4
                      "C0FFEE0102030405060708090A0B0C0D",
                      "C0FFEE0102030405060708090A0B0C0D"),
    };
    // clang-format on

    private static Invariant Assert = new Invariant();
    private static byte[] id_bytes;
    private static DummyISDApplet instance;

    protected byte cla;
    protected byte ins;
    protected byte p1;
    protected byte p2;

    public static DummyISDApplet getInstance()
    {
        return instance;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        DummyISDApplet obj
            = new DummyISDApplet(bArray, bOffset, bLength, retval);

        short aid_offset = Util.makeShort(retval[0], retval[1]);
        byte aid_len = retval[2];
        try {
            obj.register(bArray, aid_offset, aid_len);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "DummyIssuerSecurityDomain::install");
        }
        instance = obj;
    }

    private SCP02 scp02;

    @Override public final boolean select()
    {
        if (scp02 == null) {
            scp02 = new SCP02(cardKeys);
        }

        return true;
    }

    public byte[] SELECT()
    {
        return OffCard.getInstance().select(DummyISDApplet.class);
    }

    public org.globalplatform.SecureChannel getSecureChannel()
    {
        return scp02;
    }

    protected DummyISDApplet(byte[] bArray,
                             short bOffset,
                             byte bLength,
                             byte[] retval)
    {
        byte lengthAID = bArray[bOffset];
        short offsetAID = (short)(bOffset + 1);
        short offset = bOffset;
        offset += (bArray[offset]); // skip aid
        offset++;
        offset += (bArray[offset]); // skip privileges
        offset++;

        Util.setShort(retval, (short)0x0000, offsetAID);
        retval[2] = lengthAID;
        retval[3] = 0x00;
    }

    public byte[] aid()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = DummyISDApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.instanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }

    @Override public void process(APDU apdu) throws ISOException
    {
        Assert.assertTrue(scp02 != null, "Applet::secureChannel");
        Assert.assertTrue(scp02.userKeys.length > 0, "card keys");

        byte[] buffer = apdu.getBuffer();

        cla = buffer[ISO7816.OFFSET_CLA];
        ins = buffer[ISO7816.OFFSET_INS];
        p1 = buffer[ISO7816.OFFSET_P1];
        p2 = buffer[ISO7816.OFFSET_P2];

        if ((cla & (SCP02.MASK_SECURED)) == ISO7816.CLA_ISO7816) {
            if (ins == ISO7816.INS_SELECT) {
                if (!selectingApplet()) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                return;
            }
        }

        switch (ins) {
        case SCP02.INS_INITIALIZE_UPDATE:
        case ISO7816.INS_EXTERNAL_AUTHENTICATE:
        case SCP02.INS_BEGIN_RMAC_SESSION:
        case SCP02.INS_END_RMAC_SESSION:
            checkClaIsGp();
            // allow to make contactless SCP
            // checkProtocolContacted();
            processSecurity();
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    protected void processSecurity()
    {
        // send to ISD
        short responseLength = scp02.processSecurity(APDU.getCurrentAPDU());
        if (responseLength != 0) {
            APDU.getCurrentAPDU().setOutgoingAndSend(
                (short)ISO7816.OFFSET_CDATA, responseLength);
        }
    }

    protected void checkClaIsGp()
    {
        if ((cla & SCP02.MASK_GP) != SCP02.MASK_GP) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }
}

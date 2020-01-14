package org.idpass.offcard.applet;

import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.proto.SCP02SecureChannel;
import org.idpass.tools.IdpassApplet;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

@IdpassConfig(
    appletInstanceAID = "A0000001510000",
    installParams = {
        (byte)0x42
    },
    privileges = {
        (byte)0xFF,
        (byte)0xFF,
    })
public class DummyIssuerSecurityDomain
    extends IdpassApplet
{
    private static byte[] id_bytes;
    private static DummyIssuerSecurityDomain instance;

    public static DummyIssuerSecurityDomain getInstance()
    {
        return instance;
    }

    @Override public final boolean select()
    {
        if (secureChannel == null) {
            secureChannel = new SCP02SecureChannel();
        }
        return true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        instance
            = new DummyIssuerSecurityDomain(bArray, bOffset, bLength, retval);

        short aid_offset = Util.makeShort(retval[0], retval[1]);
        byte aid_len = retval[2];
        instance.register(bArray, aid_offset, aid_len);
    }

    protected DummyIssuerSecurityDomain(byte[] bArray,
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

    public byte[] id_bytes()
    {
        if (id_bytes == null) {
            IdpassConfig cfg = DummyIssuerSecurityDomain.class.getAnnotation(
                IdpassConfig.class);
            String strId = cfg.appletInstanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }

    @Override protected void processSelect()
    {
        System.out.println("*** dummy isd/cm selected ***");
    }

    @Override protected void processInternal(APDU apdu) throws ISOException
    {
        System.out.println("*** isd/cm is noop. Select applet first ***");
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}

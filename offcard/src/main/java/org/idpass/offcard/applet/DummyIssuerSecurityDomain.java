package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.proto.SCP02SecureChannel;
import org.idpass.tools.IdpassApplet;

import javacard.framework.APDU;
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
    @Override public final boolean select()
    {
        secureChannel = new SCP02SecureChannel();
        return true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        DummyIssuerSecurityDomain obj
            = new DummyIssuerSecurityDomain(bArray, bOffset, bLength, retval);

        short aid_offset = ByteBuffer.wrap(retval, 0, 2)
                               .order(ByteOrder.BIG_ENDIAN)
                               .getShort();
        byte aid_len = retval[2];
        obj.register(bArray, aid_offset, aid_len);
    }

    protected DummyIssuerSecurityDomain(byte[] bArray, short bOffset, byte bLength, byte[] retval)
    {
        byte lengthAID = bArray[bOffset];
        short offsetAID = (short)(bOffset + 1);
        short offset = bOffset;
        offset += (bArray[offset]); // skip aid
        offset++;
        offset += (bArray[offset]); // skip privileges
        offset++;

        Util.setShort(retval,(short)0x0000,offsetAID);
        retval[2] = lengthAID;
        retval[3] = 0x00;
    }

    @Override
    protected void processSelect() {

    }

    @Override
    protected void processInternal(APDU apdu) throws ISOException {

    }
}

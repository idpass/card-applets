package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CardChannel;

import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc.Params;
import org.idpass.offcard.proto.SCP02SecureChannel;
import org.idpass.offcard.proto.ICardConnection;

public class DummyIssuerSecurityDomain
    extends org.idpass.offcard.misc.DummyIssuerSecurityDomain
{
    private static String appletInstanceAID = "A0000001510000";

    private static final byte[] privileges = {
        (byte)0xFF,
        (byte)0xFF,
    };

    private static final byte[] installParams = {
        (byte)0x01,
        (byte)0x5D,
    };

    public static Params params
        = new Params(appletInstanceAID, privileges, installParams);
    ///////////////////////////////////////////////////////////////////////////
    public static ICardConnection connection;
    static private Invariant Assert = new Invariant();

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

    protected DummyIssuerSecurityDomain(byte[] bArray,
                                        short bOffset,
                                        byte bLength,
                                        byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
    }
}

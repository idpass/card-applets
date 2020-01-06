package org.idpass.offcard.applet;

import javax.smartcardio.CardChannel;

import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc.Params;
import org.idpass.offcard.proto.SCP02SecureChannel;

public class CafeBabeApplet extends org.idpass.offcard.misc.CafeBabeApplet
{
    private static String appletInstanceAID = "cafebabe4204050607";

    private static final byte[] privileges = {
        (byte)0xFF,
        (byte)0xFF,
    };

    private static final byte[] installParams = {
        (byte)0xCA,
        (byte)0xFE,
    };

    public static Params params
        = new Params(appletInstanceAID, privileges, installParams);
    ///////////////////////////////////////////////////////////////////////////
    public static CardChannel channel; // this must not be null
    static private Invariant Assert = new Invariant();

    @Override public final boolean select()
    {
        secureChannel
            = new SCP02SecureChannel(); // GPSystem.getSecureChannel();
        return true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        CafeBabeApplet obj = new CafeBabeApplet(bArray, bOffset, bLength);
        obj.register(bArray, obj.aid_offset, obj.aid_len);
    }

    protected CafeBabeApplet(byte[] bArray, short bOffset, byte bLength)
    {
        super(bArray, bOffset, bLength);
    }
}

package org.idpass.offcard.misc;

import org.idpass.tools.IdpassApplet;

import javacard.framework.APDU;
import javacard.framework.ISOException;

public class CafeBabeApplet extends IdpassApplet
{
    @Override protected void processSelect()
    {
        System.out.println("*** CafeBabeApplet::processSelect ***");
    }

    @Override protected void processInternal(APDU apdu) throws ISOException
    {
        System.out.println("*** CafeBabeApplet::processInternal ***");
    }

    protected CafeBabeApplet(byte[] bArray, short bOffset, byte bLength)
    {
        byte lengthAID = bArray[bOffset];
        short offsetAID = (short)(bOffset + 1);
        short offset = bOffset;
        offset += (bArray[offset]); // skip aid
        offset++;
        offset += (bArray[offset]); // skip privileges
        offset++;

        register(bArray, offsetAID, lengthAID);
    }
}

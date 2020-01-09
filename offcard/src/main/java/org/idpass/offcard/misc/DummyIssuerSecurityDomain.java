package org.idpass.offcard.misc;

import org.idpass.tools.IdpassApplet;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class DummyIssuerSecurityDomain extends IdpassApplet
{
    @Override protected void processSelect()
    {
        System.out.println("*** DummyIssuerSecurityDomain::processSelect ***");
    }

    @Override protected void processInternal(APDU apdu) throws ISOException
    {
        System.out.println("*** DummyIssuerSecurityDomain::processInternal ***");
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
}

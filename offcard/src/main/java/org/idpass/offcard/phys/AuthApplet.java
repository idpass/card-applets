package org.idpass.offcard.phys;

import org.idpass.offcard.interfaces.IAuthApplet;

public class AuthApplet implements IAuthApplet
{
    @Override public short AP()
    {
        return 0;
    }

    @Override public void DP(byte personaIndex)
    {
        System.out.println("");
    }

    @Override public short AL(byte[] listener)
    {
        return 0;
    }

    @Override public boolean DL(byte[] listener)
    {
        return false;
    }

    @Override public short AVP(byte personaId, byte[] authData)
    {
        return 0;
    }

    @Override public void DVP(byte personaIndex, byte verifierIndex)
    {
        System.out.println("");
    }

    @Override public int AUP(byte[] authData)
    {
        return 0;
    }

    @Override public byte[] instanceAID()
    {
        return null;
    }
}

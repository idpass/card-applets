package org.idpass.offcard.phys;

import org.idpass.offcard.interfaces.IDatastorageApplet;

public class DatastorageApplet implements IDatastorageApplet
{
    @Override public short SWITCH()
    {
        return 0;
    }

    @Override public byte[] GET_APPLICATION_IDS()
    {
        return null;
    }

    @Override public void CREATE_APPLICATION(byte[] app)
    {
        System.out.println("CREATE_APPLICATION");
    }

    @Override public void DELETE_APPLICATION(byte[] id)
    {
        System.out.println("DELETE_APPLICATION");
    }

    @Override public byte[] instanceAID()
    {
        return null;
    }
}

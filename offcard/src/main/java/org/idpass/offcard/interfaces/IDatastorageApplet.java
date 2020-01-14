package org.idpass.offcard.interfaces;

public interface IDatastorageApplet {
    public short SWITCH();
    public byte[] GET_APPLICATION_IDS();
    public void CREATE_APPLICATION(byte[] app);
    public void DELETE_APPLICATION(byte[] id);

    public byte[] instanceAID();
}

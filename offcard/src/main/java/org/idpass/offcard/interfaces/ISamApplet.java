package org.idpass.offcard.interfaces;

public interface ISamApplet {
    public byte[] ENCRYPT(byte[] inData);
    public byte[] DECRYPT(byte[] outData);

    public byte[] instanceAID();
}

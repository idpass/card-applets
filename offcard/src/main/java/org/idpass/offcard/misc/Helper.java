package org.idpass.offcard.misc;

public class Helper
{
    public static final byte[] SW9000 = new byte[] {(byte)0x90, (byte)0x00};
    public static final byte[] SW9100 = new byte[] {(byte)0x91, (byte)0x00};

    public enum Link {
        SIM,
        WIRED,
        WIRELESS;
    }

    public static byte[] arrayConcat(byte[] arr1, byte[] arr2)
    {
        byte[] arr1arr2 = new byte[arr1.length + arr2.length];

        System.arraycopy(arr1, 0, arr1arr2, 0, arr1.length);

        System.arraycopy(arr2, 0, arr1arr2, arr1.length, arr2.length);
        return arr1arr2;
    }
}

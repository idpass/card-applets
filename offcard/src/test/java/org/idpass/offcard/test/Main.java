package org.idpass.offcard.test;

import org.idpass.offcard.proto.OffCard;
import org.idpass.offcard.proto.SCP02SecureChannel;

import org.idpass.offcard.applet.AuthApplet;
import org.idpass.offcard.applet.DatastorageApplet;
import org.idpass.offcard.applet.SamApplet;

import org.testng.SkipException;
import org.testng.annotations.*;

import org.idpass.offcard.misc.Invariant;

public class Main
{
    static {
        Invariant.cflag = true;
    }

    public static void main(String[] args)
    {
        try {
        	I_SUCCESS_TEST();
        } catch (IllegalStateException e) {
            System.out.println(	
            "#####################################################\n" +
            "SOME TESTCASES FAILED\n" +
            "#####################################################\n");
        } 
    }

    @Test
    public static void I_SUCCESS_TEST() 
    {
        System.out.println(	
        "#####################################################\n" +
        "SUCCESS TEST START\n" +
        "#####################################################\n");

        short p;
        byte[] verifierTemplateData = new byte[10];

        OffCard.install(DatastorageApplet.class);
        OffCard.install(SamApplet.class);
        OffCard.install(AuthApplet.class);

        // AuthApplet tests
        OffCard.select(AuthApplet.class);
        OffCard.initializeUpdate((byte)0xCA);
       	OffCard.externalAuthenticate(SCP02SecureChannel.ENC);
        //OffCard.externalAuthenticate(SCP02SecureChannel.MAC);

        AuthApplet.AL(DatastorageApplet.params.id_bytes);
        AuthApplet.AL(SamApplet.params.id_bytes);
        p = AuthApplet.AP(); //@
        AuthApplet.AVP((byte)p, verifierTemplateData);

        OffCard.ATR();

        OffCard.select(AuthApplet.class); // resets security
        // OffCard.initializeUpdate(); // channel not secured
        AuthApplet.AUP(verifierTemplateData); //@

        // SamApplet tests
        String inData
            = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog";
        byte[] plainText = inData.getBytes();
        byte[] cipherText;
        OffCard.select(SamApplet.class);
        cipherText = SamApplet.ENCRYPT(plainText);
        byte[] decrypted = SamApplet.DECRYPT(cipherText);

        if (java.util.Arrays.equals(plainText, decrypted)) {
            System.out.println("** match ***");
        }

        // Datastorage tests
        OffCard.select(DatastorageApplet.class);
        p = DatastorageApplet.SWITCH();
        p = DatastorageApplet.SWITCH();
        p = DatastorageApplet.SWITCH();
        OffCard.select(DatastorageApplet.class);
        p = DatastorageApplet.SWITCH();

        OffCard.ATR();
        OffCard.select(DatastorageApplet.class);
        p = DatastorageApplet.SWITCH();

        OffCard.select(AuthApplet.class);
        OffCard.initializeUpdate();
        OffCard.externalAuthenticate(SCP02SecureChannel.MAC);
        AuthApplet.DP((byte)0x00); //@
        OffCard.initializeUpdate();
        OffCard.externalAuthenticate(SCP02SecureChannel.ENC);
        AuthApplet.DL(DatastorageApplet.params.id_bytes);
        AuthApplet.DL(SamApplet.params.id_bytes);

        System.out.println(	
        "#####################################################\n" +
        "SUCCESS TEST DONE\n" +
        "#####################################################\n");
    }
}

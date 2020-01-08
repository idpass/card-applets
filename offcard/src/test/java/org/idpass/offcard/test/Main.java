package org.idpass.offcard.test;

import java.util.Arrays;

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
    static
    {
        Invariant.cflag = true;
    }
    static private Invariant Assert = new Invariant(true); // hard assert

    public static void main(String[] args)
    {
        try {
            I_SUCCESS_TEST();
            DATASTORAGE_TEST();
        } catch (IllegalStateException e) {
            System.out.println(
                "#####################################################\n"
                + "SOME TESTCASES FAILED\n"
                + "#####################################################\n");
        }
    }

    @BeforeMethod public static void do_beforetest()
    {
        OffCard.initialize();
    }

    @Test public static void I_SUCCESS_TEST()
    {
        System.out.println(
            "#####################################################\n"
            + "SUCCESS TEST START\n"
            + "#####################################################\n");

        short p;
        byte[] verifierTemplateData = new byte[10];

        OffCard.install(DatastorageApplet.class);
        OffCard.install(SamApplet.class);
        OffCard.install(AuthApplet.class);

        // AuthApplet tests
        OffCard.select(AuthApplet.class);
        OffCard.initializeUpdate((byte)0xCA);
        OffCard.externalAuthenticate((byte)0b00000010); // ENC

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

        if (Arrays.equals(plainText, decrypted)) {
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
        OffCard.externalAuthenticate((byte)0b00000001); // MAC
        AuthApplet.DP((byte)0x00); //@
        OffCard.initializeUpdate();
        OffCard.externalAuthenticate((byte)0b00000010); // ENC
        AuthApplet.DL(DatastorageApplet.params.id_bytes);
        AuthApplet.DL(SamApplet.params.id_bytes);

        System.out.println(
            "#####################################################\n"
            + "SUCCESS TEST DONE\n"
            + "#####################################################\n");
    }

    @Test public static void DATASTORAGE_TEST()
    {
        System.out.println(
            "#####################################################\n"
            + "DATASTORAGE TEST START\n"
            + "#####################################################\n");

        byte[] ret = null;
        short p;
        byte[] verifierTemplateData = new byte[10];

        OffCard.install(DatastorageApplet.class);
        OffCard.install(AuthApplet.class);

        byte[] desfireCmd = {
            (byte)0x90,
            (byte)0x6A,
            (byte)0x00,
            (byte)0x00,
            (byte)0x00,
        };

        OffCard.select(AuthApplet.class);
        OffCard.initializeUpdate();
        OffCard.externalAuthenticate((byte)0b00000011);

        AuthApplet.AL(DatastorageApplet.params.id_bytes);
        p = AuthApplet.AP(); //@
        AuthApplet.AVP((byte)p, verifierTemplateData);
        AuthApplet.AUP(verifierTemplateData); //@

        OffCard.select(DatastorageApplet.class);
        DatastorageApplet.SWITCH();
        DatastorageApplet.SWITCH();
        DatastorageApplet.SWITCH();

        ret = DatastorageApplet.GET_APPLICATION_IDS();

        byte[] app01 = {
            (byte)0xAA,
            (byte)0xAA,
            (byte)0xAA,
            (byte)0x11,
            (byte)0x11,
        };
        byte[] app02 = {
            (byte)0xBB,
            (byte)0xBB,
            (byte)0xBB,
            (byte)0x22,
            (byte)0x22,
        };
        byte[] app03 = {
            (byte)0xCC,
            (byte)0xCC,
            (byte)0xCC,
            (byte)0x33,
            (byte)0x33,
        };

        DatastorageApplet.CREATE_APPLICATION(app01);
        DatastorageApplet.CREATE_APPLICATION(app02);
        DatastorageApplet.CREATE_APPLICATION(app03);

        ret = DatastorageApplet.GET_APPLICATION_IDS();
        byte[] expected = {
            (byte)0xAA,
            (byte)0xAA,
            (byte)0xAA,
            (byte)0xBB,
            (byte)0xBB,
            (byte)0xBB,
            (byte)0xCC,
            (byte)0xCC,
            (byte)0xCC,
        };

        Assert.assertTrue(Arrays.equals(ret, expected),
                          "three desfire applist");

        // deleting in this order for now, pending investigation why deleting in
        // the middle or in the front sparsely confuses datastorage resulting to
        // holes
        DatastorageApplet.DELETE_APPLICATION(
            new byte[] {(byte)0xCC, (byte)0xCC, (byte)0xCC});
        ret = DatastorageApplet.GET_APPLICATION_IDS();
        Assert.assertTrue(Arrays.equals(ret,
                                        new byte[] {(byte)0xAA,
                                                    (byte)0xAA,
                                                    (byte)0xAA,
                                                    (byte)0xBB,
                                                    (byte)0xBB,
                                                    (byte)0xBB}),
                          "desfire applist - 1");
        DatastorageApplet.DELETE_APPLICATION(
            new byte[] {(byte)0xBB, (byte)0xBB, (byte)0xBB});
        ret = DatastorageApplet.GET_APPLICATION_IDS();
        Assert.assertTrue(
            Arrays.equals(ret, new byte[] {(byte)0xAA, (byte)0xAA, (byte)0xAA}),
            "desfire applist - 2");
        DatastorageApplet.DELETE_APPLICATION(
            new byte[] {(byte)0xAA, (byte)0xAA, (byte)0xAA});
        ret = DatastorageApplet.GET_APPLICATION_IDS();
        Assert.assertTrue(ret == null, "desfire applist should be zero");

        OffCard.ATR();
        OffCard.select(DatastorageApplet.class);

        System.out.println(
            "#####################################################\n"
            + "DATASTORAGE TEST END\n"
            + "#####################################################\n");
    }
}

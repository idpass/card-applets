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
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.security.Security;
// import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.idpass.offcard.misc.Helper;

public class Main
{
    static
    {
        Assert = new Invariant(true); // hard assert
        Invariant.cflag = true;
        // Security.addProvider(new BouncyCastleProvider());
    }
    private static Invariant Assert;

    private static byte[] verifierTemplateData = Hex.decode(
        "B6F82993D970F0B7CE15AFE9FE892ECA29E1F64383647E37B0A878FA3F8D2DA7D87DF54C946C72A70F57E7F63C69DF8EF68ACD09862AF6CBAF9B92FC6A8A87687872402C19A2841B354C35979EF07420A06A989F952B524462F0E10AC5F2AA1CBE3342B7BABD594E898EE474AE3F774ECAEA48727DB3A7F63206F637A673BA06350FCC201DE7C20417AEB1076D734EEEA1689A603A385FCF");
    private static byte[] candidate = Hex.decode(
        "7F2E868184268B8129A7402DAC91335793342B8437814237C24238D34238E0423EEE423F4F43433F44521A45662D956D664470745379F2527DE64286EF42905B8697939297A0919AF3929F8D94A2878FA3948FA4A250AB854CB0C651B8CF41B8DA51CAA050D03C4CD54D5DD7175BDBBB50E0255CE5415DE72C4CE7FE41F1B05EF2914EF9C880FC258B");
    private static byte[] pin6 = Hex.decode("313233343536");

    static byte[] app01 = {
        (byte)0xAA,
        (byte)0xAA,
        (byte)0xAA,
        (byte)0x11,
        (byte)0x11,
    };
    static byte[] app02 = {
        (byte)0xBB,
        (byte)0xBB,
        (byte)0xBB,
        (byte)0x22,
        (byte)0x22,
    };
    static byte[] app03 = {
        (byte)0xCC,
        (byte)0xCC,
        (byte)0xCC,
        (byte)0x33,
        (byte)0x33,
    };

    static byte[] app010203 = {
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

    public static void main(String[] args)
    {
        try {
            I_SUCCESS_TEST();
            DATASTORAGE_TEST();
        } catch (IllegalStateException e) {
            System.out.println("*** CATCHALL IllegalStateException ***");
        } catch (RuntimeException e) {
            System.out.println("*** CATCHALL RunTimeException ***");
        } catch (Exception e) {
            System.out.println("*** CATCHALL Exception ***");
        }

        Invariant.check();
    }

    @BeforeMethod public static void do_beforetest()
    {
        OffCard.reInitialize();
    }

    @Test 
    public static void I_SUCCESS_TEST()
    {
        System.out.println(
            "#####################################################\n"
            + "I_SUCCESS TEST START\n"
            + "#####################################################\n");

        short p;

        OffCard offcard = OffCard.createInstance(Helper.getjcardsimChannel());

        offcard.install(DatastorageApplet.class);
        offcard.install(SamApplet.class);
        offcard.install(AuthApplet.class);

        // AuthApplet tests
        offcard.select(AuthApplet.class);
        offcard.initializeUpdate();
        offcard.externalAuthenticate((byte)0b0010); // ENC

        AuthApplet auth = AuthApplet.getInstance();
        DatastorageApplet datastorage = DatastorageApplet.getInstance();
        SamApplet sam = SamApplet.getInstance();

        auth.AL(datastorage.instanceAID());
        auth.AL(sam.instanceAID());
        p = auth.AP(); //@
        auth.AVP((byte)p, pin6); // pin set at AuthApplet annotation

        offcard.ATR();

        offcard.select(AuthApplet.class); // resets security
        // offcard.initializeUpdate(); // channel not secured
        auth.AUP(pin6); //@

        // SamApplet tests
        String inData
            = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog";
        byte[] plainText = inData.getBytes();
        byte[] cipherText;
        offcard.select(SamApplet.class);
        cipherText = sam.ENCRYPT(plainText);
        byte[] decrypted = sam.DECRYPT(cipherText);

        if (Arrays.equals(plainText, decrypted)) {
            System.out.println("** match ***");
        }

        // Datastorage tests
        offcard.select(DatastorageApplet.class);
        p = datastorage.SWITCH();
        p = datastorage.SWITCH();
        p = datastorage.SWITCH();
        offcard.select(DatastorageApplet.class);
        p = datastorage.SWITCH();

        offcard.ATR();
        offcard.select(DatastorageApplet.class);
        p = datastorage.SWITCH();

        offcard.select(AuthApplet.class);
        offcard.initializeUpdate();
        offcard.externalAuthenticate((byte)0b00000001); // MAC
        auth.DP((byte)0x00); //@
        offcard.initializeUpdate();
        offcard.externalAuthenticate((byte)0b00000010); // ENC
        auth.DL(datastorage.instanceAID());
        auth.DL(sam.instanceAID());

        System.out.println(
            "#####################################################\n"
            + "SUCCESS TEST DONE\n"
            + "#####################################################\n");
        Invariant.check();
    }

    @Test 
    public static void DATASTORAGE_TEST()
    {
        System.out.println(
            "#####################################################\n"
            + "DATASTORAGE TEST START\n"
            + "#####################################################\n");

        OffCard offcard = OffCard.createInstance(Helper.getjcardsimChannel());

        byte[] ret = null;
        short p;
        byte[] verifierTemplateData = new byte[10];

        offcard.install(DatastorageApplet.class);
        offcard.install(AuthApplet.class);

        AuthApplet auth = AuthApplet.getInstance();
        DatastorageApplet datastorage = DatastorageApplet.getInstance();

        byte[] desfireCmd = {
            (byte)0x90,
            (byte)0x6A,
            (byte)0x00,
            (byte)0x00,
            (byte)0x00,
        };

        offcard.select(AuthApplet.class);
        offcard.initializeUpdate();
        offcard.externalAuthenticate((byte)(Helper.GP.C_DECRYPTION | Helper.GP.C_MAC));

        auth.AL(datastorage.instanceAID());
        p = auth.AP(); //@
        auth.AVP((byte)p, verifierTemplateData);
        auth.AUP(verifierTemplateData); //@

        offcard.select(DatastorageApplet.class);
        datastorage.SWITCH();
        datastorage.SWITCH();
        datastorage.SWITCH();

        ret = datastorage.GET_APPLICATION_IDS();

        datastorage.CREATE_APPLICATION(app01);
        datastorage.CREATE_APPLICATION(app02);
        datastorage.CREATE_APPLICATION(app03);

        ret = datastorage.GET_APPLICATION_IDS();

        Assert.assertTrue(Arrays.equals(ret, app010203),
                          "three desfire applist");

        // deleting in this order for now, pending investigation why deleting in
        // the middle or in the front sparsely confuses datastorage resulting to
        // holes
        datastorage.DELETE_APPLICATION(
            new byte[] {(byte)0xCC, (byte)0xCC, (byte)0xCC});
        ret = datastorage.GET_APPLICATION_IDS();
        Assert.assertTrue(Arrays.equals(ret,
                                        new byte[] {(byte)0xAA,
                                                    (byte)0xAA,
                                                    (byte)0xAA,
                                                    (byte)0xBB,
                                                    (byte)0xBB,
                                                    (byte)0xBB}),
                          "desfire applist - 1");
        datastorage.DELETE_APPLICATION(
            new byte[] {(byte)0xBB, (byte)0xBB, (byte)0xBB});
        ret = datastorage.GET_APPLICATION_IDS();
        Assert.assertTrue(
            Arrays.equals(ret, new byte[] {(byte)0xAA, (byte)0xAA, (byte)0xAA}),
            "desfire applist - 2");
        datastorage.DELETE_APPLICATION(
            new byte[] {(byte)0xAA, (byte)0xAA, (byte)0xAA});
        ret = datastorage.GET_APPLICATION_IDS();
        Assert.assertTrue(ret == null, "desfire applist should be zero");

        offcard.ATR();
        offcard.select(DatastorageApplet.class);

        System.out.println(
            "#####################################################\n"
            + "DATASTORAGE TEST END\n"
            + "#####################################################\n");

        Invariant.check();
    }

    // Assuming all applets installed up to:
    //  - AL ${datastorageInstanceAID}
    //  - AP
    //  - AVP 00 ${verifierTemplateData}
    //  - AUP
    // 
    // This setups datastorage to switch propertly
    // and at least 1 persona for testing
    //@Test
    public static void PHYSICAL_CARD_TEST()
    {
        System.setProperty("comlink", "wired");

        OffCard offcard = OffCard.createInstance(Helper.getPcscChannel());

        offcard.install(AuthApplet.class);
        offcard.install(DatastorageApplet.class);

        AuthApplet auth = AuthApplet.getInstance();
        DatastorageApplet datastorage = DatastorageApplet.getInstance();

        offcard.select_cm();
        offcard.select(AuthApplet.class);
        
        // Check initial secure channel handshake 
        offcard.initializeUpdate();
        offcard.externalAuthenticate((byte)0b0011); // ENC, MAC

        // Temporarily clear secure channel, pending todo in IV chaining.
        // The IV is not yet fully synchronized and subsequent secure messages
        // past secure channel handshake fails to verify
        offcard.initializeUpdate();

        auth.AUP(candidate);
        offcard.select(DatastorageApplet.class);

        datastorage.SWITCH();
        offcard.select(DatastorageApplet.class);
        datastorage.SWITCH();
    }

}


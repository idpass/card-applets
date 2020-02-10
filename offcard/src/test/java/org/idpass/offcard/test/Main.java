package org.idpass.offcard.test;

import java.util.Arrays;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

import org.idpass.offcard.proto.OffCard;
import org.idpass.offcard.proto.SCP02;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.idpass.offcard.applet.AuthApplet;
import org.idpass.offcard.applet.DatastorageApplet;
import org.idpass.offcard.applet.SamApplet;
import org.idpass.offcard.applet.SignApplet;

import org.testng.annotations.*;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.RawTransaction;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;
import org.idpass.offcard.misc.Invariant;
// import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.Hex;
import java.security.Security;
import org.idpass.offcard.misc.Helper;
import javacard.framework.Util;
import javax.smartcardio.CardException;
import org.idpass.offcard.misc.Dump;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;

public class Main
{
    static
    {
        Assert = new Invariant(true); // hard assert
    }
    private static Invariant Assert;
    // TODO: Convert this long ascii string to pure byte array initialization
    private static byte[] verifierTemplateData = Hex.decode(
        "8200910210007F2E868184268B8129A7402DAC91335793342B8437814237C24238D34238E0423EEE423F4F43433F44521A45662D956D664470745379F2527DE64286EF42905B8697939297A0919AF3929F8D94A2878FA3948FA4A250AB854CB0C651B8CF41B8DA51CAA050D03C4CD54D5DD7175BDBBB50E0255CE5415DE72C4CE7FE41F1B05EF2914EF9C880FC258B");

    private static byte[] candidate = Hex.decode(
        "7F2E868184268B8129A7402DAC91335793342B8437814237C24238D34238E0423EEE423F4F43433F44521A45662D956D664470745379F2527DE64286EF42905B8697939297A0919AF3929F8D94A2878FA3948FA4A250AB854CB0C651B8CF41B8DA51CAA050D03C4CD54D5DD7175BDBBB50E0255CE5415DE72C4CE7FE41F1B05EF2914EF9C880FC258B");
    private static byte[] pin6 = Hex.decode("313233343536");
    private static byte[] pin7 = Hex.decode("31323334353637");

    private final static short MINIMUM_SUCCESSFUL_MATCH_SCORE = 0x4000;

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
            signTransactionTest();
            // test_SignApplet_physical();
            // test_SignApplet_virtual();
            // verifierTemplateTest_physical_card();
            // circleci_I_SUCCESS_TEST();
            // circleci_DATASTORAGE_TEST();
            // circleci_persona_add_delete();
        } catch (CardException e) {
        } catch (IllegalStateException e) {
            System.out.println("ERROR IllegalStateException: " + e.getCause());
        } catch (RuntimeException e) {
            System.out.println("ERROR RunTimeException: " + e.getCause());
        } catch (Exception e) {
            System.out.println("ERROR Exception: " + e.getCause());
        }

        Invariant.check();
    }

    @BeforeMethod public static void circleci_do_beforetest()
    {
        OffCard.reInitialize();
    }

    @Test public static void circleci_I_SUCCESS_TEST() throws CardException
    {
        System.out.println(
            "#####################################################\n"
            + "I_SUCCESS TEST START\n"
            + "#####################################################\n");

        short p;

        OffCard offcard = OffCard.getInstance();

        DatastorageApplet datastorage
            = (DatastorageApplet)offcard.INSTALL(DatastorageApplet.class);
        SamApplet sam = (SamApplet)offcard.INSTALL(SamApplet.class);
        AuthApplet auth = (AuthApplet)offcard.INSTALL(AuthApplet.class);

        // AuthApplet tests
        auth.SELECT();
        offcard.INITIALIZE_UPDATE();
        offcard.EXTERNAL_AUTHENTICATE((byte)0b0010); // ENC

        auth.processAddListener(datastorage.aid());
        auth.processAddListener(sam.aid());
        p = auth.processAddPersona(); //@
        auth.processAddVerifierForPersona(
            (byte)p, pin6); // pin set at AuthApplet annotation

        offcard.ATR();

        auth.SELECT();
        // offcard.INITIALIZE_UPDATE(); // channel not secured
        auth.processAuthenticatePersona(pin6); //@

        // SamApplet tests
        String inData
            = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog";
        byte[] plainText = inData.getBytes();
        byte[] cipherText;
        sam.SELECT();
        cipherText = sam.processEncrypt(plainText);
        byte[] decrypted = sam.processDecrypt(cipherText);

        if (Arrays.equals(plainText, decrypted)) {
            System.out.println("** match ***");
        }

        // Datastorage tests
        datastorage.SELECT();
        p = datastorage.processSwitchNextVirtualCard();
        p = datastorage.processSwitchNextVirtualCard();
        p = datastorage.processSwitchNextVirtualCard();
        datastorage.SELECT();
        p = datastorage.processSwitchNextVirtualCard();

        offcard.ATR();
        datastorage.SELECT();
        p = datastorage.processSwitchNextVirtualCard();

        auth.SELECT();
        offcard.INITIALIZE_UPDATE();
        offcard.EXTERNAL_AUTHENTICATE((byte)0b00000001); // MAC
        auth.processDeletePersona((byte)0x00); //@
        offcard.INITIALIZE_UPDATE();
        offcard.EXTERNAL_AUTHENTICATE((byte)0b00000010); // ENC
        auth.processDeleteListener(datastorage.aid());
        auth.processDeleteListener(sam.aid());

        System.out.println(
            "#####################################################\n"
            + "SUCCESS TEST DONE\n"
            + "#####################################################\n");
        Invariant.check();
    }

    @Test public static void circleci_persona_add_delete() throws CardException
    {
        byte[] byteseq = {};

        OffCard card = OffCard.getInstance();
        AuthApplet auth = (AuthApplet)card.INSTALL(AuthApplet.class);

        byteseq = auth.SELECT();
        Assert.assertTrue(Helper.checkstatus(byteseq));

        short index = auth.processAddPersona();
        Assert.assertEquals(index, (short)0xFFFF);

        byteseq = card.INITIALIZE_UPDATE();
        Assert.assertTrue(byteseq.length == 30);
        Assert.assertTrue(Helper.checkstatus(byteseq));

        card.EXTERNAL_AUTHENTICATE(SCP02.C_MAC);
        index = auth.processAddPersona();
        Assert.assertEquals(index, (short)0x0000);

        card.ATR();

        index = auth.processAddPersona();
        Assert.assertEquals(index, (short)0xFFFF);

        card.ATR();

        byteseq = card.EXTERNAL_AUTHENTICATE(SCP02.C_MAC);
        Assert.assertFalse(Helper.checkstatus(byteseq));
        Assert.assertEquals(byteseq, Helper.SW6985);

        byteseq = card.INITIALIZE_UPDATE();
        Assert.assertTrue(Helper.checkstatus(byteseq));
        byteseq = card.EXTERNAL_AUTHENTICATE(SCP02.C_MAC);
        Assert.assertTrue(Helper.checkstatus(byteseq));
        index = auth.processAddPersona();
        Assert.assertEquals(index, (short)0xFFFF);

        auth.SELECT();
        card.INITIALIZE_UPDATE();
        card.EXTERNAL_AUTHENTICATE(SCP02.C_MAC);

        index = auth.processAddPersona();
        Assert.assertEquals(index, (short)0x0001);
        index = auth.processAddPersona();
        Assert.assertEquals(index, (short)0x0002);

        card.ATR();
        byteseq = auth.SELECT();
        Assert.assertTrue(Helper.checkstatus(byteseq));
        short count = Util.makeShort(byteseq[0], byteseq[1]);
        Assert.assertEquals((short)3, count, "Added 3 Personas");

        card.INITIALIZE_UPDATE();
        card.EXTERNAL_AUTHENTICATE(SCP02.C_MAC);
        auth.processDeletePersona((byte)0);

        byteseq = auth.SELECT();
        count = Util.makeShort(byteseq[0], byteseq[1]);

        auth.processDeletePersona((byte)1);
        byteseq = auth.SELECT();
        count = Util.makeShort(byteseq[0], byteseq[1]);
        Assert.assertEquals((short)2, count, "Delete requires secure channel");

        card.INITIALIZE_UPDATE();
        card.EXTERNAL_AUTHENTICATE(SCP02.C_MAC);
        auth.processDeletePersona((byte)1);
        auth.processDeletePersona((byte)2);
        byteseq = auth.SELECT();
        count = Util.makeShort(byteseq[0], byteseq[1]);
        Assert.assertEquals((short)0, count, "Deleted 3 Personas");
    }

    @Test public static void circleci_DATASTORAGE_TEST() throws CardException
    {
        System.out.println(
            "#####################################################\n"
            + "DATASTORAGE TEST START\n"
            + "#####################################################\n");

        OffCard offcard = OffCard.getInstance();

        byte[] ret = null;
        short p;
        byte[] verifierTemplateData = new byte[10];

        DatastorageApplet datastorage
            = (DatastorageApplet)offcard.INSTALL(DatastorageApplet.class);
        AuthApplet auth = (AuthApplet)offcard.INSTALL(AuthApplet.class);

        byte[] desfireCmd = {
            (byte)0x90,
            (byte)0x6A,
            (byte)0x00,
            (byte)0x00,
            (byte)0x00,
        };

        auth.SELECT();
        offcard.INITIALIZE_UPDATE();
        offcard.EXTERNAL_AUTHENTICATE((byte)(SCP02.C_DECRYPTION | SCP02.C_MAC));

        auth.processAddListener(datastorage.aid());
        p = auth.processAddPersona(); //@
        auth.processAddVerifierForPersona((byte)p, verifierTemplateData);
        auth.processAuthenticatePersona(verifierTemplateData); //@

        datastorage.SELECT();
        datastorage.processSwitchNextVirtualCard();
        datastorage.processSwitchNextVirtualCard();
        datastorage.processSwitchNextVirtualCard();

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
        datastorage.SELECT();

        System.out.println(
            "#####################################################\n"
            + "DATASTORAGE TEST END\n"
            + "#####################################################\n");

        Invariant.check();
    }

    // Assuming all applets installed up to:
    //  - processAddListener ${datastorageInstanceAID}
    //  - processAddPersona
    //  - processAddVerifierForPersona 00 ${verifierTemplateData}
    //  - processAuthenticatePersona
    //
    // This setups datastorage to switch propertly
    // and at least 1 persona for testing
    @Test public static void PHYSICAL_CARD_TEST() throws CardException
    {
        OffCard offcard = OffCard.getInstance(Helper.getPcscChannel());
        if (offcard == null) {
            System.out.println(
                "No physical reader/card found. Gracefully exiting.");
            return;
        }

        DatastorageApplet datastorage
            = (DatastorageApplet)offcard.INSTALL(DatastorageApplet.class);
        AuthApplet auth = (AuthApplet)offcard.INSTALL(AuthApplet.class);

        offcard.SELECT_CM();
        auth.SELECT();

        // Check initial secure channel handshake
        offcard.INITIALIZE_UPDATE();
        offcard.EXTERNAL_AUTHENTICATE((byte)0b0011); // ENC, MAC

        // Temporarily clear secure channel, pending todo in IV chaining.
        // The IV is not yet fully synchronized and subsequent secure messages
        // past secure channel handshake fails to verify
        offcard.INITIALIZE_UPDATE();

        auth.processAuthenticatePersona(candidate);
        datastorage.SELECT();

        datastorage.processSwitchNextVirtualCard();
        datastorage.SELECT();
        datastorage.processSwitchNextVirtualCard();

        Invariant.check();
    }

    @Test
    public static void test_SignApplet_virtual()
        throws CardException, UnsupportedEncodingException
    {
        byte[] data = "hello world test message".getBytes("UTF-8");
        byte[] ret = {};

        OffCard card = OffCard.getInstance();
        SignApplet signer = (SignApplet)card.INSTALL(SignApplet.class);
        AuthApplet auth = (AuthApplet)card.INSTALL(AuthApplet.class);

        auth.SELECT();
        card.INITIALIZE_UPDATE();
        card.EXTERNAL_AUTHENTICATE((byte)0b0011);
        auth.processAddListener(signer.aid());
        short index = auth.processAddPersona();
        auth.processAddVerifierForPersona((byte)index, pin6);
        auth.processAuthenticatePersona(pin7);

        ret = signer.SELECT();
        Dump.print(ret, "SignApplet select retval");

        ret = signer.sign(data);
        Dump.print(ret, "signature");
        Assert.assertTrue(ret.length == 0);

        auth.SELECT();
        // auth.processAddListener(signer.aid()); // sign applet must listen
        card.INITIALIZE_UPDATE();
        card.EXTERNAL_AUTHENTICATE((byte)0b0011);
        auth.processAuthenticatePersona(pin6);

        signer.SELECT();
        ret = signer.sign(data);
        Dump.print(ret, "signature");
        Assert.assertTrue(ret.length > 0);

        Invariant.check();
    }

    @Test
    public static void test_SignApplet_physical()
        throws CardException, UnsupportedEncodingException
    {
        byte[] data = "hello world test message".getBytes("UTF-8");
        byte[] ret = {};

        OffCard card = OffCard.getInstance(Helper.getPcscChannel());
        if (card == null) {
            System.out.println(
                "No physical reader/card found. Gracefully exiting.");
            return;
        }
        SignApplet signer = (SignApplet)card.INSTALL(SignApplet.class);
        AuthApplet auth = (AuthApplet)card.INSTALL(AuthApplet.class);

        auth.SELECT();
        card.INITIALIZE_UPDATE();
        card.EXTERNAL_AUTHENTICATE((byte)0b0011);
        auth.processAddListener(signer.aid());
        short index = auth.processAddPersona();
        auth.processAddVerifierForPersona((byte)index, verifierTemplateData);
        auth.processAuthenticatePersona(pin7);

        ret = signer.SELECT();
        Dump.print(ret, "SignApplet select retval");

        ret = signer.sign(data);
        Dump.print(ret, "signature");
        Assert.assertTrue(ret.length == 0);

        auth.SELECT();
        card.INITIALIZE_UPDATE();
        card.EXTERNAL_AUTHENTICATE((byte)0b0011);
        auth.processAuthenticatePersona(candidate);

        signer.SELECT();
        ret = signer.sign(data);
        Dump.print(ret, "signature");
        Assert.assertTrue(ret.length > 0);

        Invariant.check();
    }

    @Test
    public static void verifierTemplateTest_physical_card() throws CardException
    {
        Security.addProvider(new BouncyCastleProvider());
        boolean physical = true;

        OffCard offcard = null;

        if (physical) {
            offcard = OffCard.getInstance(Helper.getPcscChannel());
        } else {
            offcard = OffCard.getInstance();
        }

        if (offcard == null) {
            System.out.println(
                "No physical reader/card found. Gracefully exiting.");
            return;
        }

        short n = (short)0xFFFF;
        byte[] byteseq = {};

        DatastorageApplet datastorage
            = (DatastorageApplet)offcard.INSTALL(DatastorageApplet.class);
        AuthApplet auth = (AuthApplet)offcard.INSTALL(AuthApplet.class);

        offcard.SELECT_CM();
        byteseq = auth.SELECT();
        Dump.print(byteseq);

        offcard.INITIALIZE_UPDATE();
        offcard.EXTERNAL_AUTHENTICATE((byte)0b0011); // ENC+MAC

        auth.processAddListener(datastorage.aid());
        n = auth.processAddPersona();
        auth.processAddVerifierForPersona((byte)n, verifierTemplateData);

        if (physical) {
            int score = auth.processAuthenticatePersona(candidate);
            System.out.println(String.format("score = 0x%08X", score));
            Assert.assertEquals((short)(score & 0xFFFF),
                                MINIMUM_SUCCESSFUL_MATCH_SCORE,
                                "biometrics pass");
        } else {
            int score = auth.processAuthenticatePersona(candidate);
            System.out.println(String.format("score = 0x%08X", score));
            Assert.assertEquals(
                (short)(score & 0xFFFF), 0x0000, "simple pin match");
        }
        byteseq = datastorage.SELECT();
        Dump.print(byteseq);
        n = datastorage.processSwitchNextVirtualCard();
        byteseq = datastorage.SELECT();
        Dump.print(byteseq);
        n = datastorage.processSwitchNextVirtualCard();

        Invariant.check();
    }

    // NOTE: verifier type setting is set in class annotation
    @Test public static void pin6MatchTest() throws CardException
    {
        Security.addProvider(new BouncyCastleProvider());

        OffCard offcard = OffCard.getInstance();

        short n = (short)0xFFFF;
        byte[] byteseq = {};

        DatastorageApplet datastorage
            = (DatastorageApplet)offcard.INSTALL(DatastorageApplet.class);
        AuthApplet auth = (AuthApplet)offcard.INSTALL(AuthApplet.class);

        offcard.SELECT_CM();
        byteseq = auth.SELECT();
        Dump.print(byteseq);

        offcard.INITIALIZE_UPDATE();
        offcard.EXTERNAL_AUTHENTICATE((byte)0b0011); // ENC+MAC

        auth.processAddListener(datastorage.aid());
        n = auth.processAddPersona();
        auth.processAddVerifierForPersona((byte)n, pin6);

        int score = auth.processAuthenticatePersona(pin6);
        System.out.println(String.format("score = 0x%08X", score));
        Assert.assertEquals(score, 0x00000000, "pin match score 100%");
        byteseq = datastorage.SELECT();
        Dump.print(byteseq);
        n = datastorage.processSwitchNextVirtualCard();
        byteseq = datastorage.SELECT();
        Dump.print(byteseq);
        n = datastorage.processSwitchNextVirtualCard();

        Invariant.check();
    }

    static void signTransactionTest() throws Exception
    {
        OffCard card = null;
        card = OffCard.getInstance();

        SignApplet signer = (SignApplet)card.INSTALL(SignApplet.class);
        AuthApplet auth = (AuthApplet)card.INSTALL(AuthApplet.class);

        auth.SELECT();
        card.INITIALIZE_UPDATE();
        card.EXTERNAL_AUTHENTICATE((byte)0b0011);

        auth.processAddListener(signer.aid());
        short index = auth.processAddPersona();

        auth.processAddVerifierForPersona((byte)index, pin6);
        auth.processAuthenticatePersona(pin6);

        byte[] ret = signer.SELECT();

        String wallet1_privk
            = "bd65457f5f410787c5bcbaa2d97a5ec1cd7a2e0315fd33c52b361a207eec3123";
        Credentials wallet1 = Credentials.create(wallet1_privk);
        String wallet1_address = wallet1.getAddress();

        card.INITIALIZE_UPDATE();
        card.EXTERNAL_AUTHENTICATE((byte)0b0011);
        signer.processLoadKey(wallet1.getEcKeyPair());
        card.INITIALIZE_UPDATE();

        String wallet2_privk
            = "67c095f769ea8120c3ffd8d6054876986dcad016a386bc30fb176e77590adce0";
        Credentials wallet2 = Credentials.create(wallet2_privk);
        String wallet2_address = wallet2.getAddress();

        Web3j web3j = Web3j.build(new HttpService("http://localhost:8545"));

        // Verify balance
        System.out.println(
            "Wallet 1 balance: "
            + web3j
                  .ethGetBalance(wallet1.getAddress(),
                                 DefaultBlockParameterName.LATEST)
                  .send()
                  .getBalance());
        System.out.println(
            "Wallet 2 balance: "
            + web3j
                  .ethGetBalance(wallet2.getAddress(),
                                 DefaultBlockParameterName.LATEST)
                  .send()
                  .getBalance());

        // Create transaction
        BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
        BigInteger weiValue
            = Convert.toWei(BigDecimal.valueOf(1.0), Convert.Unit.FINNEY)
                  .toBigIntegerExact();
        BigInteger nonce
            = web3j
                  .ethGetTransactionCount(wallet1.getAddress(),
                                          DefaultBlockParameterName.LATEST)
                  .send()
                  .getTransactionCount();

        RawTransaction rawTransaction
            = RawTransaction.createEtherTransaction(nonce,
                                                    gasPrice,
                                                    Transfer.GAS_LIMIT,
                                                    wallet2.getAddress(),
                                                    weiValue);

        // Sign transaction
        byte[] txBytes = TransactionEncoder.encode(rawTransaction);
        Sign.SignatureData signature = signMessage(txBytes, signer);

        Method encode = TransactionEncoder.class.getDeclaredMethod(
            "encode", RawTransaction.class, Sign.SignatureData.class);
        encode.setAccessible(true);

        // Send transaction
        byte[] signedMessage
            = (byte[])encode.invoke(null, rawTransaction, signature);
        String hexValue = "0x" + Hex.toHexString(signedMessage);
        EthSendTransaction ethSendTransaction
            = web3j.ethSendRawTransaction(hexValue).send();

        if (ethSendTransaction.hasError()) {
            System.out.println("Transaction Error: "
                               + ethSendTransaction.getError().getMessage());
        }

        Assert.assertFalse(ethSendTransaction.hasError());
    }

    private static Sign.SignatureData signMessage(byte[] message,
                                                  SignApplet signer)
        throws Exception
    {
        byte[] messageHash = Hash.sha3(message);
        byte[] rawSig = signer.sign(messageHash);

        int rLen = rawSig[3];
        int sOff = 6 + rLen;
        int sLen = rawSig.length - rLen - 6;

        BigInteger r = new BigInteger(Arrays.copyOfRange(rawSig, 4, 4 + rLen));
        BigInteger s
            = new BigInteger(Arrays.copyOfRange(rawSig, sOff, sOff + sLen));

        Class<?> ecdsaSignature
            = Class.forName("org.web3j.crypto.Sign$ECDSASignature");
        Constructor ecdsaSignatureConstructor
            = ecdsaSignature.getDeclaredConstructor(BigInteger.class,
                                                    BigInteger.class);
        ecdsaSignatureConstructor.setAccessible(true);
        Object sig = ecdsaSignatureConstructor.newInstance(r, s);
        Method m = ecdsaSignature.getMethod("toCanonicalised");
        m.setAccessible(true);
        sig = m.invoke(sig);

        Method recoverFromSignature = Sign.class.getDeclaredMethod(
            "recoverFromSignature", int.class, ecdsaSignature, byte[].class);
        recoverFromSignature.setAccessible(true);

        byte[] pubData = signer.processGetPubKey();
        BigInteger publicKey
            = new BigInteger(Arrays.copyOfRange(pubData, 1, pubData.length));

        int recId = -1;
        for (int i = 0; i < 4; i++) {
            BigInteger k = (BigInteger)recoverFromSignature.invoke(
                null, i, sig, messageHash);
            if (k != null && k.equals(publicKey)) {
                recId = i;
                break;
            }
        }
        if (recId == -1) {
            throw new RuntimeException(
                "Could not construct a recoverable key. This should never happen.");
        }

        int headerByte = recId + 27;

        Field rF = ecdsaSignature.getDeclaredField("r");
        rF.setAccessible(true);
        Field sF = ecdsaSignature.getDeclaredField("s");
        sF.setAccessible(true);
        r = (BigInteger)rF.get(sig);
        s = (BigInteger)sF.get(sig);

        // 1 header + 32 bytes for R + 32 bytes for S
        byte v = (byte)headerByte;
        byte[] rB = Numeric.toBytesPadded(r, 32);
        byte[] sB = Numeric.toBytesPadded(s, 32);

        return new Sign.SignatureData(v, rB, sB);
    }
}

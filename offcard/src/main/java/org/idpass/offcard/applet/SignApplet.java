package org.idpass.offcard.applet;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.web3j.crypto.ECKeyPair;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc.Helper;
import org.idpass.offcard.proto.OffCard;

import javacard.framework.SystemException;
import javacard.framework.Util;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;

@IdpassConfig(
    packageAID  = "F769647061737304",
    appletAID   = "F769647061737304010001",
    instanceAID = "F76964706173730401000101",
    capFile = "sign.cap",
    installParams = {
        (byte)0x9E,
    },
    privileges = { 
        (byte)0xFF,
        (byte)0xFF,
    }
)
public class SignApplet
        extends org.idpass.sign.SignApplet
{
    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static byte[] id_bytes;
    private static SignApplet instance;

    private static Invariant Assert = new Invariant();

    byte[] appletPub;

    private SecureRandom random;

    private ECParameterSpec ecSpec;
    private KeyPairGenerator kpg;

    private KeyAgreement ka;
    private KeyPair kp;
    private ECPublicKey pubKey;
    private ECPrivateKey privKey;
    private Signature signer;
    private static KeyFactory kf;

    private byte[] sharedSecret;

    CommandAPDU command;
    ResponseAPDU response;
    byte[] lastResult;

    public static SignApplet getInstance()
    {
        return instance;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        SignApplet applet = new SignApplet(bArray, bOffset, bLength);

        try {
            applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "SignApplet::install");
        }

        instance = applet;
    }

    private SignApplet(byte[] bArray, short bOffset, byte bLength)
    {
        super(bArray, bOffset, bLength);

        try {
            random = new SecureRandom();
            ka = KeyAgreement.getInstance("ECDH", "BC");
            ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

            kpg = KeyPairGenerator.getInstance("ECDH", "BC");
            kpg.initialize(ecSpec, random);

            kp = kpg.generateKeyPair();

            kf = KeyFactory.getInstance("ECDSA", "BC");

            kp = kpg.genKeyPair();
            privKey = (ECPrivateKey)kp.getPrivate();
            pubKey = (ECPublicKey)kp.getPublic();

            ka.init(privKey);
            signer = Signature.getInstance("SHA256withECDSA", "BC");

        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    @Override public final boolean select()
    {
        if (secureChannel == null) {
            secureChannel = DummyISDApplet.getInstance().getSecureChannel();
        }
        secureChannel.resetSecurity();
        return true;
    }

    public byte[] SELECT()
    {
        appletPub = null;
        byte[] ret = Helper.SW6999;
        byte[] result = OffCard.getInstance().select(SignApplet.class);

        ResponseAPDU response = new ResponseAPDU(result);

        if (response.getSW() == 0x9000) {
            int len = result.length - 2;
            byte[] remotePublicKey = new byte[len];
            Util.arrayCopyNonAtomic(
                result, (short)0, remotePublicKey, (short)0, (short)(len));
            if (true == establishSecret(remotePublicKey)) {
                appletPub = remotePublicKey;
                ret = remotePublicKey;
            }
        }

        return ret;
    }

    private boolean establishSecret(byte[] pubkey)
    {
        try {
            ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(
                ecSpec.getCurve().decodePoint(pubkey), ecSpec);

            ECPublicKey cardKey = (ECPublicKey)kf.generatePublic(cardKeySpec);

            ka.doPhase(cardKey, true);
            sharedSecret = ka.generateSecret();
            CommandAPDU command
                = new CommandAPDU(0x00,
                                  INS_ESTABLISH_SECRET,
                                  0,
                                  0,
                                  pubKey.getQ().getEncoded(false));

            ResponseAPDU response = OffCard.getInstance().Transmit(command);
            if (response.getSW() == 0x9000) {
                return true;
            }
        } catch (Exception e) {
            // System.out.println(e.getMessage());
        }

        return false;
    }

    public byte[] aid()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = SignApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.instanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }

    public byte[] sign(byte[] input)
    {
        byte[] signature = {};

        command = new CommandAPDU(0x00, INS_SIGN, 0, 0, input);

        response = OffCard.getInstance().Transmit(command);

        if (response.getSW() != 0x9000) {
            return signature;
        }

        // Receive applet's signature to lastResult
        lastResult = response.getData();
        signature = lastResult;

        /*ECPublicKeySpec pubkSpec = new ECPublicKeySpec(
            ecSpec.getCurve().decodePoint(appletPub), ecSpec);

        try {
            ECPublicKey publicKey = (ECPublicKey)kf.generatePublic(pubkSpec);

            signer.initVerify(publicKey);
            signer.update(input);
            if (signer.verify(lastResult)) {
                signature = lastResult;
            }

            signature = lastResult;
        } catch (InvalidKeySpecException | InvalidKeyException
                 | SignatureException e) {
            // e.printStackTrace();
        }*/

        return signature;
    }

    // This requires encrypted security level
    public boolean processLoadKey(ECKeyPair keyPair)
    {
        byte[] pubkey = keyPair.getPublicKey().toByteArray();
        byte[] privkey = keyPair.getPrivateKey().toByteArray();

        boolean flag = false;
        byte[] data = {};
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(32);
        bos.write(privkey, 1, (short)32);
        bos.write(pubkey.length + 1);
        bos.write((byte)0x04);
        bos.write(pubkey, 0, pubkey.length);
        data = bos.toByteArray();

        command = new CommandAPDU(0x00, INS_LOAD_KEYPAIR, 0, 0, data);
        response = OffCard.getInstance().Transmit(command);
        flag = response.getSW() == 0x9000;

        return flag;
    }

    public byte[] processGetPubKey()
    {
        byte[] pubkey = {};

        command = new CommandAPDU(0x00, INS_GET_PUBKEY, 0, 0);
        response = OffCard.getInstance().Transmit(command);
        pubkey = response.getData();
        return pubkey;
    }
}

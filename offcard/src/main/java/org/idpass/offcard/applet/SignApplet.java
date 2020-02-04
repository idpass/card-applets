package org.idpass.offcard.applet;

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
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
import org.idpass.offcard.misc._o;
import org.idpass.offcard.proto.OffCard;

import com.licel.jcardsim.bouncycastle.util.Arrays;

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
        (byte)0x42,
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

    private static final byte[] pubkey_bytes = Hex.decode(
        "3056301006072a8648ce3d020106052b8104000a034200049637ca26fe119e9eb8bdd3182e0eb874ceccc5941a80c25fba4075671e490cd4e8a4d1d6732cef71684e470f2d5dff732a7bf2c689216b763b6969dcb6e9312e");
    private static final byte[] privkey_bytes = Hex.decode(
        "303e020100301006072a8648ce3d020106052b8104000a04273025020101042048473c3a25f85f2d47b5da42e18fa37c1698e2808ca2c524bb144117f8b06f3d");

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
        byte[] retval = new byte[4];
        SignApplet applet = new SignApplet(bArray, bOffset, bLength, null);

        short aid_offset = Util.makeShort(retval[0], retval[1]);
        byte aid_len = retval[2];

        try {
            applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "SignApplet::install");
        }

        instance = applet;
    }

    private SignApplet(byte[] bArray,
                       short bOffset,
                       byte bLength,
                       byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);

        try {
            random = new SecureRandom();
            ka = KeyAgreement.getInstance("ECDH", "BC");
            ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

            kpg = KeyPairGenerator.getInstance("ECDH", "BC");
            kpg.initialize(ecSpec, random);

            kp = kpg.generateKeyPair();

            kf = KeyFactory.getInstance("ECDSA", "BC");

            if (privkey_bytes != null && pubkey_bytes != null) {
                X509EncodedKeySpec x509 = new X509EncodedKeySpec(pubkey_bytes);
                pubKey = (ECPublicKey)kf.generatePublic(x509);

                PKCS8EncodedKeySpec pkcs8
                    = new PKCS8EncodedKeySpec(privkey_bytes);
                privKey = (ECPrivateKey)kf.generatePrivate(pkcs8);
            } else {
                kp = kpg.genKeyPair();
                privKey = (ECPrivateKey)kp.getPrivate();
                pubKey = (ECPublicKey)kp.getPublic();
            }

            ka.init(privKey);
            signer = Signature.getInstance("SHA256withECDSA", "BC");

        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | InvalidAlgorithmParameterException | InvalidKeyException
                 | InvalidKeySpecException e) {
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
        byte[] ret = {};
        byte[] result = OffCard.getInstance().select(SignApplet.class);

        ResponseAPDU response = new ResponseAPDU(result);

        if (response.getSW() == 0x9000) {
            int len = result.length - 2;
            byte[] tmpbuf = new byte[len];
            Util.arrayCopyNonAtomic(
                result, (short)0, tmpbuf, (short)0, (short)(len));
            sharedSecret = establishSecret(tmpbuf);
            if (sharedSecret != null) {
                appletPub = tmpbuf;
                ret = tmpbuf;
            }
        }

        return ret;
    }

    private byte[] establishSecret(byte[] pubkey)
    {
        try {
            ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(
                ecSpec.getCurve().decodePoint(pubkey), ecSpec);

            ECPublicKey cardKey = (ECPublicKey)kf.generatePublic(cardKeySpec);

            ka.doPhase(cardKey, true);
            byte[] secret = ka.generateSecret();
            _o.o_(secret, "offcard shared_secret");

            CommandAPDU command
                = new CommandAPDU(0x00,
                                  INS_ESTABLISH_SECRET,
                                  0,
                                  0,
                                  pubKey.getQ().getEncoded(false));

            ResponseAPDU response = OffCard.getInstance().Transmit(command);
            if (response.getSW() == 0x9000) {
                if (Arrays.areEqual(response.getData(), secret)) {
                    return secret;
                } else {
                    System.out.println("-- secrets mismatch --");
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        return null;
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
            System.out.println("*** sign error ***");
            return null;
        }

        // Receive applet's signature to lastResult
        lastResult = response.getData();

        ECPublicKeySpec pubkSpec = new ECPublicKeySpec(
            ecSpec.getCurve().decodePoint(appletPub), ecSpec);

        try {
            ECPublicKey publicKey = (ECPublicKey)kf.generatePublic(pubkSpec);

            signer.initVerify(publicKey);
            signer.update(input);
            if (signer.verify(lastResult)) {
                System.out.println("-- sign ok ---");
                signature = lastResult;
            } else {
                System.out.println("-- sign error ---");
            }
        } catch (InvalidKeySpecException | InvalidKeyException
                 | SignatureException e) {
            // e.printStackTrace();
            System.out.println(e.getMessage());
        }

        return signature;
    }
}

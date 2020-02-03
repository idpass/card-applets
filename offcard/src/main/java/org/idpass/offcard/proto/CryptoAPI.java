package org.idpass.offcard.proto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import java.security.Key;
import java.security.GeneralSecurityException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.idpass.offcard.misc._o;

import javacard.framework.Util;
import javacard.security.KeyPair;

import java.security.Security;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.ECPoint;

public class CryptoAPI
{
    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final byte[] constENC = new byte[] {(byte)0x01, (byte)0x82};
    public static final byte[] constMAC = new byte[] {(byte)0x01, (byte)0x01};
    public static final byte[] constDEK = new byte[] {(byte)0x01, (byte)0x81};

    public static final byte[] NullBytes8
        = new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    static final IvParameterSpec iv_null_8 = new IvParameterSpec(NullBytes8);

    public static void init()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] deriveSCP02SessionKey(byte[] cardKey,
                                               byte[] seq,
                                               byte[] purposeData)
    {
        byte[] key24 = resizeDES(cardKey, 24);

        try {
            byte[] derivationData = new byte[16];
            // 2 bytes constant
            System.arraycopy(purposeData, 0, derivationData, 0, 2);
            // 2 bytes sequence counter + 12 bytes 0x00
            System.arraycopy(seq, 0, derivationData, 2, 2);

            SecretKeySpec tmpKey = new SecretKeySpec(key24, "DESede");

            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", "BC");
            cipher.init(
                Cipher.ENCRYPT_MODE, tmpKey, new IvParameterSpec(NullBytes8));

            return cipher.doFinal(derivationData);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("error generating session keys.",
                                            e);
        } catch (InvalidKeyException | IllegalBlockSizeException
                 | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("error generating session keys.", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("SpongyCastle not installed");
        }
    }

    public static byte[] resizeDES(byte[] key, int length)
    {
        if (length == 24) {
            byte[] key24 = new byte[24];
            System.arraycopy(key, 0, key24, 0, 16);
            System.arraycopy(key, 0, key24, 16, 8);
            return key24;
        } else {
            byte[] key8 = new byte[8];
            System.arraycopy(key, 0, key8, 0, 8);
            return key8;
        }
    }

    public static byte[] calcCryptogram(byte[] text, byte[] sENC)
    {
        byte[] d = pad80(text, 8);
        Key key24 = new SecretKeySpec(resizeDES(sENC, 24), "DESede");

        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(
                Cipher.ENCRYPT_MODE, key24, new IvParameterSpec(NullBytes8));
            byte[] result = new byte[8];
            byte[] res = cipher.doFinal(d, 0, d.length); // -des-ede-cbc
            // byte[] res = cipher.doFinal(text, 0, text.length); //
            // -des-ede-cbc
            System.arraycopy(res, res.length - 8, result, 0, 8);
            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("MAC computation failed.", e);
        }
    }

    // byte[] mac = computeMAC(apdu,initV,k);
    public static byte[] computeMAC(byte[] data, byte[] icv, byte[] sMAC)
    {
        byte[] d = pad80(data, 8);

        try {
            Cipher cipher1 = Cipher.getInstance("DES/CBC/NoPadding");
            cipher1.init(Cipher.ENCRYPT_MODE,
                         new SecretKeySpec(resizeDES(sMAC, 8), "DES"),
                         new IvParameterSpec(icv));
            Cipher cipher2 = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher2.init(Cipher.ENCRYPT_MODE,
                         new SecretKeySpec(resizeDES(sMAC, 24), "DESede"),
                         new IvParameterSpec(icv));

            byte[] result = new byte[8];
            byte[] temp;

            if (d.length > 8) {
                // doFinal(byte[] input, int inputOffset, int inputLen)
                temp = cipher1.doFinal(d, 0, d.length - 8); // -des-cbc
                System.arraycopy(temp, temp.length - 8, result, 0, 8);
                //                     ---------------
                //                     ^
                //                     |_ move pointer to last 8 bytes
                cipher2.init(Cipher.ENCRYPT_MODE,
                             new SecretKeySpec(resizeDES(sMAC, 24), "DESede"),
                             new IvParameterSpec(result));
            }
            byte[] t = new byte[8];
            System.arraycopy(d, (0 + d.length) - 8, t, 0, 8);
            temp = cipher2.doFinal(d, (0 + d.length) - 8, 8); // -des-ede-cbc
            System.arraycopy(temp, temp.length - 8, result, 0, 8);
            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("MAC computation failed.", e);
        }
    }

    public static byte[] pad80(byte[] text, int blocksize)
    {
        int total = (text.length / blocksize + 1) * blocksize;
        byte[] result = Arrays.copyOfRange(text, 0, total);
        result[text.length] = (byte)0x80;
        return result;
    }

    public static byte[] unpad80(byte[] text)
    {
        try {
            if (text.length < 1)
                throw new BadPaddingException("Invalid ISO 7816-4 padding");
            int offset = text.length - 1;
            while (offset > 0 && text[offset] == 0) {
                offset--;
            }
            if (text[offset] != (byte)0x80) {
                throw new BadPaddingException("Invalid ISO 7816-4 padding");
            }
            return Arrays.copyOf(text, offset);
        } catch (BadPaddingException e) {
            System.out.println("unpad80 error");
        }

        return null;
    }

    public static byte[] updateIV(byte[] prevIV, byte[] sMAC)
    {
        try {
            byte[] k8 = resizeDES(sMAC, 8);
            Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
            SecretKeySpec keyspec = new SecretKeySpec(k8, "DES");
            c.init(Cipher.ENCRYPT_MODE, keyspec);

            byte[] newIv = c.doFinal(prevIV); // -des-ecb
            return newIv;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("computation failed.", e);
        }
    }

    /*
    # better to display by od:
    openssl enc -des-ede-cbc \
        -K $sENC${sENC:0:16} \
        -iv 0000000000000000 \
        -in ~/helloworld_pad80.hex | od
    */
    public static byte[] encryptData(byte[] data, byte[] sENC)
    {
        byte[] padded = pad80(data, 8);

        try {
            Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
            Key k = new SecretKeySpec(resizeDES(sENC, 24), "DESede");
            c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(NullBytes8));
            return c.doFinal(padded); // -des-ede-cbc
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("error: encryptData failed", e);
        }
    }

    /**
     * Decrypts the response from the card using the session key. The returned
     * data is already stripped from IV and padding and can be potentially
     * empty.
     *
     * @param data the ciphetext
     * @return the plaintext
     */
    public static byte[] decryptData(byte[] data, byte[] sENC)
    {
        try {
            Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
            Key k = new SecretKeySpec(resizeDES(sENC, 24), "DESede");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(NullBytes8);
            c.init(Cipher.DECRYPT_MODE, k, ivParameterSpec);
            byte[] x = c.doFinal(data);
            byte[] unpaddedx = unpad80(x);
            return unpaddedx;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Is BouncyCastle in the classpath?", e);
        }
    }

    ///////////////// byte[] <==> ECPublicKey,ECPrivateKey ////////////////////
    public static byte[] fromECPrivateKey(javacard.security.ECPrivateKey key)
    {
        byte[] byteseq = {};

        if (key.isInitialized()) {
            short n = (short)(key.getSize() / 8);
            byteseq = new byte[n];
            short retval = key.getS(byteseq, (short)0);
            // Assert.assertEquals(retval,n, "javacard ECPrivateKey len
            // anomaly");
            return byteseq;
        }

        return byteseq;
    }

    public static byte[] fromECPublicKey(javacard.security.ECPublicKey key)
    {
        byte[] byteseq = {};

        if (key.isInitialized()) {
            short n = (short)(key.getSize() / 8);
            n = 65; // always 65
            byteseq = new byte[n];
            short retval = key.getW(byteseq, (short)0);
            // Assert.assertEquals(retval,n, "javacard ECPublicKey len 65
            // anomaly");
            return byteseq;
        }

        return byteseq;
    }

    public static byte[] fromECPublicKey(
        java.security.interfaces.ECPublicKey key)
    {
        int keyLengthBytes = key.getParams().getOrder().bitLength() / Byte.SIZE;
        byte[] publkeybytes = new byte[2 * keyLengthBytes];

        int offset = 0;

        BigInteger x = key.getW().getAffineX();
        byte[] xba = x.toByteArray();
        if (xba.length > keyLengthBytes + 1
            || xba.length == keyLengthBytes + 1 && xba[0] != 0) {
            throw new IllegalStateException(
                "X coordinate of EC public key has wrong size");
        }

        if (xba.length == keyLengthBytes + 1) {
            System.arraycopy(xba, 1, publkeybytes, offset, keyLengthBytes);
        } else {
            System.arraycopy(xba,
                             0,
                             publkeybytes,
                             offset + keyLengthBytes - xba.length,
                             xba.length);
        }
        offset += keyLengthBytes;

        BigInteger y = key.getW().getAffineY();
        byte[] yba = y.toByteArray();
        if (yba.length > keyLengthBytes + 1
            || yba.length == keyLengthBytes + 1 && yba[0] != 0) {
            throw new IllegalStateException(
                "Y coordinate of EC public key has wrong size");
        }

        if (yba.length == keyLengthBytes + 1) {
            System.arraycopy(yba, 1, publkeybytes, offset, keyLengthBytes);
        } else {
            System.arraycopy(yba,
                             0,
                             publkeybytes,
                             offset + keyLengthBytes - yba.length,
                             yba.length);
        }

        return publkeybytes;
    }

    public static byte[] fromECPrivateKey(
        java.security.interfaces.ECPrivateKey key)
    {
        int keyLengthBytes = key.getParams().getOrder().bitLength() / Byte.SIZE;
        byte[] privkeybytes = new byte[keyLengthBytes];
        int offset = 0;

        BigInteger x = key.getS();
        byte[] xba = x.toByteArray();
        if (xba.length > keyLengthBytes + 1
            || xba.length == keyLengthBytes + 1 && xba[0] != 0) {
            throw new IllegalStateException("ERROR");
        }

        if (xba.length == keyLengthBytes + 1) {
            System.arraycopy(xba, 1, privkeybytes, offset, keyLengthBytes);
        } else {
            System.arraycopy(xba,
                             0,
                             privkeybytes,
                             offset + keyLengthBytes - xba.length,
                             xba.length);
        }

        return privkeybytes;
    }

    /*
    public static void secret(byte[] b)
    {
        try {
            CryptoAPI.init();

            KeyPairGenerator kpgen;
            kpgen = KeyPairGenerator.getInstance("ECDH", "BC");

            ECGenParameterSpec genspec = new ECGenParameterSpec("secp256k1");
            kpgen.initialize(genspec);

            java.security.KeyPair localKeyPair = kpgen.generateKeyPair();
            // java.security.KeyPair remoteKeyPair = kpgen.generateKeyPair();

            _o.o_(b);

            // test creation
            ECPublicKey remoteKey = constructECPublicKey(
                ((ECPublicKey)localKeyPair.getPublic()).getParams(), b);

            // local key agreement
            javax.crypto.KeyAgreement localKA
                = javax.crypto.KeyAgreement.getInstance("ECDH");
            localKA.init(localKeyPair.getPrivate());
            localKA.doPhase(remoteKey, false);
            byte[] localSecret = localKA.generateSecret();

            _o.o_(localSecret);

        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | InvalidAlgorithmParameterException | InvalidKeySpecException
                 | InvalidKeyException e) {
            e.printStackTrace();
        }
    }
    */

    public static java.security.interfaces.ECPublicKey
    constructECPublicKey(java.security.spec.ECParameterSpec params,
                         byte[] pubkey)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        int keySizeBytes = params.getOrder().bitLength() / Byte.SIZE;

        int offset = 0;
        BigInteger x = new BigInteger(
            1, Arrays.copyOfRange(pubkey, offset, offset + keySizeBytes));
        offset += keySizeBytes;
        BigInteger y = new BigInteger(
            1, Arrays.copyOfRange(pubkey, offset, offset + keySizeBytes));
        ECPoint w = new ECPoint(x, y);

        ECPublicKeySpec otherKeySpec = new ECPublicKeySpec(w, params);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPublicKey otherKey
            = (ECPublicKey)keyFactory.generatePublic(otherKeySpec);

        return otherKey;
    }

}

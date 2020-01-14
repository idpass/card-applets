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
import java.security.Security;

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
}

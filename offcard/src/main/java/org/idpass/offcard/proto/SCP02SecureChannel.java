package org.idpass.offcard.proto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.idpass.offcard.misc.Helper;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc._o;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import java.security.SecureRandom;
import java.util.Arrays;

public class SCP02SecureChannel implements org.globalplatform.SecureChannel
{
    private static Invariant Assert = new Invariant();

    public static final byte INITIALIZE_UPDATE = (byte)0x50;
    public static final byte EXTERNAL_AUTHENTICATE = (byte)0x82;

    // GlobalPlatform Card Specification 2.1.1
    // E.1.2 Entity Authentication
    private static short secureChannelSequenceCounter = (short)0xBABE;

    private static byte[] diversification_data = {
        (byte)0x01,
        (byte)0x02,
        (byte)0x03,
        (byte)0x04,
        (byte)0x05,
        (byte)0x06,
        (byte)0x07,
        (byte)0x08,
        (byte)0x09,
        (byte)0x0A,
    };

    private static byte[] _icv = CryptoAPI.NullBytes8.clone();

    private byte[] keySetting = {
        (byte)0xFF,
        (byte)0x02, // scp02
    };

    public SCP02Keys keys[];

    public byte[] sessionENC;
    public byte[] sessionMAC;
    public byte[] sessionDEK;

    public boolean bInitUpdated = false;
    public byte securityLevel = 0x00;

    public byte[] card_challenge = new byte[8]; // Card generates this
    public byte[] host_challenge = new byte[8]; // OffCard generates this
    public byte[] keyInfoResponse = new byte[2];

    public static int count;

    public SCP02SecureChannel(SCP02Keys[] keys)
    {
        count++;
        System.out.println("SCP02SecureChannel:" + count);

        // One for DummyIssuerSecurityDomain (not used)
        // One for OffCard
        // One common for every IDPass applets
        Assert.assertTrue(count <= 3, "SCP02SecureChannel::constructor");
        if (keys != null) {
            this.keys = keys.clone();
            byte preferred = (byte)Helper.getRandomKvno(keys.length);
            keySetting[0] = preferred;
        }
    }

    @Override public short processSecurity(APDU apdu) throws ISOException
    {
        short responseLength = 0;
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
        case INITIALIZE_UPDATE:
            byte reqkvno = buffer[ISO7816.OFFSET_P1]; // requested keyset#
            byte index = reqkvno;

            // Card Specification V2.3.1 | GPC_SPE_034 (Mar 2018)
            // E.5.1.3 Reference Control Parameter P1 - Key Version Number
            if (reqkvno == 0x00) {
                index = keySetting[0];
                // reqkvno = index;
            }

            byte[] kEnc = null;
            byte[] kMac = null;
            byte[] kDek = null;

            if (index == (byte)0xFF) {
                kEnc = Helper.nxpDefaultKey;
                kMac = Helper.nxpDefaultKey;
                kDek = Helper.nxpDefaultKey;
            } else {
                try {
                    kEnc = keys[index - 1].kEnc;
                    kMac = keys[index - 1].kMac;
                    kDek = keys[index - 1].kDek;

                    _o.o_(kEnc);

                } catch (java.lang.ArrayIndexOutOfBoundsException e) {
                    /*
                    Based on jcop terminal, the SW_KEY_NOT_FOUND (0x6A88) only
                    happens when the requested keyindex is not found in the
                    card.

                    If the requested keyindex is found in the card, but is not
                    found in the offcard, then the card return value is 0x9000
                    but the card reader emits message:

                    Command failed: No such key: 1/1
                    */

                    // Table E-9: INITIALIZE UPDATE Error Condition
                    ISOException.throwIt((short)Helper.SW_KEY_NOT_FOUND);
                }
            }

            SecureRandom random = new SecureRandom();
            byte[] cardrandom = new byte[6]; // card generates 6 random bytes
            random.nextBytes(cardrandom);
            byte[] scsc = new byte[2];
            Util.setShort(scsc, (short)0, secureChannelSequenceCounter);
            card_challenge = Helper.arrayConcat(scsc, cardrandom);

            // Copy host_challenge
            Util.arrayCopyNonAtomic(buffer,
                                    (short)ISO7816.OFFSET_CDATA,
                                    host_challenge,
                                    (short)0x00,
                                    (byte)host_challenge.length);

            sessionENC = CryptoAPI.deriveSCP02SessionKey(
                kEnc, scsc, CryptoAPI.constENC);
            sessionMAC = CryptoAPI.deriveSCP02SessionKey(
                kMac, scsc, CryptoAPI.constMAC);
            sessionDEK = CryptoAPI.deriveSCP02SessionKey(
                kDek, scsc, CryptoAPI.constDEK);

            // Compute sENC:
            // sENC =
            // des_ede_cbc(KEY,nullbytes8,scp02const_0182,card_challenge[0:2]);

            // Compute card_cryptogram:
            // card_cryptogram = des_ede_cbc(resize8(sENC),nullbytes8,
            // [host_challenge + card_challenge]);
            byte[] hostcard_challenge
                = Helper.arrayConcat(host_challenge, card_challenge);

            byte[] card_cryptogram
                = CryptoAPI.calcCryptogram(hostcard_challenge, sessionENC);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try {
                // Prepare card response to offcard
                bos.write(diversification_data);
                // bos.write(cardKeyInformation);
                bos.write(index);
                bos.write(keySetting[1]);
                bos.write(card_challenge);
                bos.write(card_cryptogram);
            } catch (IOException e) {
                e.printStackTrace();
            }

            byte[] response = bos.toByteArray();

            // Write response to buffer
            responseLength = (short)response.length;
            Util.arrayCopyNonAtomic(response,
                                    (short)0,
                                    buffer,
                                    (short)ISO7816.OFFSET_CDATA,
                                    responseLength);
            bInitUpdated = true;
            securityLevel = 0x00; // clear security
            break;

        case EXTERNAL_AUTHENTICATE:
            byte[] mdata = new byte[13];
            Util.arrayCopyNonAtomic(
                buffer, (short)0, mdata, (short)0x00, (byte)mdata.length);

            byte sL = buffer[ISO7816.OFFSET_P1];
            // Copy host_cryptogram
            // This is a computation from offcard based
            // on [card_challenge + host_challenge], and the session key
            byte[] host_cryptogram = new byte[8];
            Util.arrayCopyNonAtomic(buffer,
                                    (short)ISO7816.OFFSET_CDATA,
                                    host_cryptogram,
                                    (short)0x00,
                                    (byte)host_cryptogram.length);
            // Get mac
            byte[] mac = new byte[8];
            Util.arrayCopyNonAtomic(buffer,
                                    (short)(ISO7816.OFFSET_CDATA + 8),
                                    mac,
                                    (short)0x00,
                                    (byte)mac.length);

            ///
            byte[] icv;
            if (Arrays.equals(_icv, CryptoAPI.NullBytes8)) {
                icv = _icv;
            } else {
                icv = CryptoAPI.updateIV(_icv, sessionMAC);
            }

            // compute mac here
            byte[] mcompute = CryptoAPI.computeMAC(mdata, icv, sessionMAC);
            boolean cryptogram_mac_correct = false;

            byte[] cardhost_challenge
                = Helper.arrayConcat(card_challenge, host_challenge);

            byte[] cgram
                = CryptoAPI.calcCryptogram(cardhost_challenge, sessionENC);

            Assert.assertEquals(
                cgram, host_cryptogram, "Cryptogram ext-auth card");

            if (Arrays.equals(mac, mcompute)
                && Arrays.equals(cgram, host_cryptogram)) {
                cryptogram_mac_correct = true;
            }

            if (bInitUpdated == true && cryptogram_mac_correct) {
                securityLevel = (byte)(securityLevel | buffer[2] | 0x80);
                bInitUpdated = false;
                responseLength = 0;
                secureChannelSequenceCounter++;
                break;
            } else {
                resetSecurity();
                throw new IllegalStateException(
                    "Command failed: No previous initialize update");
            }
        }

        return responseLength;
    }

    @Override public void resetSecurity()
    {
        // System.out.println("SecureChannel::resetSecurity");
        bInitUpdated = false;
        securityLevel = 0x00;
    }

    @Override
    public short unwrap(byte[] buf, short arg1, short arg2) throws ISOException
    {
        byte cla = buf[ISO7816.OFFSET_CLA];
        if ((securityLevel & (Helper.GP.C_DECRYPTION | Helper.GP.C_MAC)) != 0) {
            if ((cla & 0x04) == 0) {
                resetSecurity();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }

        return arg2;
    }

    @Override
    public short wrap(byte[] buf, short arg1, short arg2)
        throws ArrayIndexOutOfBoundsException, ISOException
    {
        byte cla = buf[ISO7816.OFFSET_CLA];
        if ((securityLevel & (Helper.GP.C_DECRYPTION | Helper.GP.C_MAC)) != 0) {
            if ((cla & 0x04) == 0) {
                resetSecurity();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }

        return arg2;
    }

    @Override
    public short decryptData(byte[] buf, short arg1, short arg2)
        throws ISOException
    {
        byte cla = buf[ISO7816.OFFSET_CLA];
        if ((securityLevel & (Helper.GP.C_DECRYPTION | Helper.GP.C_MAC)) != 0) {
            if ((cla & 0x04) == 0) {
                resetSecurity();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }

        System.out.println("SecureChannel::decryptData");
        return 0;
    }

    @Override
    public short encryptData(byte[] buf, short arg1, short arg2)
        throws ArrayIndexOutOfBoundsException
    {
        byte cla = buf[ISO7816.OFFSET_CLA];
        if ((securityLevel & (Helper.GP.C_DECRYPTION | Helper.GP.C_MAC)) != 0) {
            if ((cla & 0x04) == 0) {
                resetSecurity();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }

        System.out.println("SecureChannel::encryptData");
        return 0;
    }

    @Override public byte getSecurityLevel()
    {
        return securityLevel;
    }
}

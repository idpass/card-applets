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

    public static int count;

    public static void reInitialize()
    {
        count = 0;
    }

    public byte[] icv;

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

    public byte[] card_challenge = new byte[8]; 
    public byte[] host_challenge = new byte[8]; 
    public byte[] keyInfoResponse = new byte[2];

    public byte[] computeMac(byte[] input)
    {
        byte[] icv;

        if (Arrays.equals(this.icv, CryptoAPI.NullBytes8)) {
            icv = this.icv;
        } else {
            icv = CryptoAPI.updateIV(this.icv, this.sessionMAC);
        }

        byte[] mac = CryptoAPI.computeMAC(input, icv, sessionMAC);
        this.icv = mac.clone();

        return mac;
    }

    public byte[] calcCryptogram(byte[] input)
    {
        byte[] cgram = CryptoAPI.calcCryptogram(input, sessionENC);
        return cgram;
    }

    public boolean setKeyIndex(int index, byte[] seq)
    {
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
                _o.o_(kEnc, "off-card key");

            } catch (java.lang.ArrayIndexOutOfBoundsException e) {
                /*String info = String.format(
                    "Command failed: No such key: 0x%02X/0x%02X",
                    kvno,
                    index);
                System.out.println(info);
                return cardresponse; */
                return false;
            }
        }

        sessionENC
            = CryptoAPI.deriveSCP02SessionKey(kEnc, seq, CryptoAPI.constENC);
        sessionMAC
            = CryptoAPI.deriveSCP02SessionKey(kMac, seq, CryptoAPI.constMAC);
        sessionDEK
            = CryptoAPI.deriveSCP02SessionKey(kDek, seq, CryptoAPI.constDEK);

        return true;
    }

    public SCP02SecureChannel(SCP02Keys[] keys)
    {
        this.icv = CryptoAPI.NullBytes8.clone();
        count++;

        // One for DummyIssuerSecurityDomain
        // One common for every IDPass applets
        Assert.assertTrue(count <= 2, "SCP02SecureChannel::constructor");
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
            }

            SecureRandom random = new SecureRandom();
            byte[] cardrandom = new byte[6]; // card generates 6 random bytes
            random.nextBytes(cardrandom);
            byte[] seq = new byte[2];
            Util.setShort(seq, (short)0, secureChannelSequenceCounter);

            if (setKeyIndex(index, seq) == false) {
                ISOException.throwIt((short)Helper.SW_KEY_NOT_FOUND);
            }

            card_challenge = Helper.arrayConcat(seq, cardrandom);

            // Copy host_challenge
            Util.arrayCopyNonAtomic(buffer,
                                    (short)ISO7816.OFFSET_CDATA,
                                    host_challenge,
                                    (short)0x00,
                                    (byte)host_challenge.length);

            byte[] hostcard_challenge
                = Helper.arrayConcat(host_challenge, card_challenge);

            byte[] card_cryptogram = calcCryptogram(hostcard_challenge);

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

            byte[] computedMac = computeMac(mdata);

            boolean cryptogram_ok = false;
            boolean mac_ok = false;

            byte[] cardhost_challenge
                = Helper.arrayConcat(card_challenge, host_challenge);

            byte[] computedHostCryptogram
                = calcCryptogram(cardhost_challenge);

            Assert.assertEquals(computedHostCryptogram,
                                host_cryptogram,
                                "Cryptogram ext-auth card");

            if (Arrays.equals(computedHostCryptogram, host_cryptogram)) {
                cryptogram_ok = true;
            }

            if (Arrays.equals(mac, computedMac)) {
                mac_ok = true;
            }

            if (bInitUpdated == true && cryptogram_ok && mac_ok) {
                securityLevel = (byte)(securityLevel | buffer[2] | 0x80);
                bInitUpdated = false;
                responseLength = 0;
                secureChannelSequenceCounter++;
                break;
            } else {
                resetSecurity();

                if (!bInitUpdated) {
                    // "Command failed: No previous initialize update"
                    ISOException.throwIt(
                        (short)ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

                if (!cryptogram_ok) {
                    // Table E-12
                    ISOException.throwIt((short)Helper.SW_VERIFICATION_FAILED);
                }

                if (!mac_ok) {
                    ISOException.throwIt(
                        (short)ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
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

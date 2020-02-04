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

import org.bouncycastle.util.encoders.Hex;

// clang-format off
// CLA Byte Coding (not Security Level)
// 8 7 6 5 4 3 2 1  
// 0 0 0 0 - - - - Command defined in ISO/IEC 7816
// 1 0 0 0 - - - - GlobalPlatform command
// - 0 0 0 0 0 - - No secure messaging
// - 0 0 0 0 1 - - Secure messaging - GlobalPlatform proprietary
// - 0 0 0 1 0 - - Secure messaging - ISO/IEC 7816 standard, command header not processed (no C-MAC)
// - 0 0 0 1 1 - - Secure messaging - ISO/IEC 7816 standard, command header authenticated (C-MAC)
// - 0 0 0 - - x x Logical channel number 

public class SCP02 implements org.globalplatform.SecureChannel
{
    public static final byte[] nxpDefaultKey = Hex.decode("404142434445464748494a4b4c4d4e4F");
    public static final byte[] otherTestKey  = Hex.decode("CAFEBABE11223344CAFEBABE11223344");

    public static final byte SECURE_MESSAGING_GP        = (byte)0b00000100;  
    public static final byte SECURE_MESSAGING_ISO       = (byte)0b00001000;  
    public static final byte MASK_SECURED               = (byte)0b00001100;  
    public static final byte MASK_GP                    = (byte)0b10000000;

    public static final byte ANY_AUTHENTICATED          = (byte)0b01000000;

    private static Invariant Assert = new Invariant();

    public static final byte INS_INITIALIZE_UPDATE = (byte)0x50;
    public static final byte INS_BEGIN_RMAC_SESSION = (byte)0x7A;
    public static final byte INS_END_RMAC_SESSION = (byte)0x78;

    // GlobalPlatform Card Specification 2.1.1 E.1.2 Entity Authentication
    private static short sequenceCounter = (short)0xAAA0;
    private static byte[] diversification_data = Hex.decode("0102030405060708090A");
    // clang-format on

    public static int count;

    public static void reInitialize()
    {
        count = 0;
    }

    public byte[] icv;
    public byte cla;
    public String entity;

    private byte[] keySetting = {
        (byte)0xFF,
        (byte)0x02, // scp02
    };

    public SCP02Keys userKeys[];

    public byte[] sessionENC;
    public byte[] sessionMAC;
    public byte[] sessionDEK;

    public boolean bInitUpdated = false;
    public byte securityLevel = 0x00;

    public byte[] card_challenge = new byte[8];
    public byte[] host_challenge = new byte[8];

    public byte[] computeMac(byte[] input)
    {
        byte[] icv;

        if (Arrays.equals(this.icv, CryptoAPI.NullBytes8)) {
            icv = this.icv;
        } else {
            icv = CryptoAPI.updateIV(this.icv, this.sessionMAC);
        }

        _o.o_(icv, String.format("MAC IV %s", entity));
        byte[] mac = CryptoAPI.computeMAC(input, icv, sessionMAC);
        this.icv = mac.clone();

        System.out.println(String.format("sMAC  = %s", _o.O_(this.sessionMAC)));
        System.out.println(String.format("input = %s", _o.O_(input)));
        System.out.println(String.format("mac   = %s", _o.O_(mac)));

        return mac;
    }

    public byte[] calcCryptogram(byte[] input)
    {
        byte[] cgram = null;

        if (input != null && input.length > 0 && sessionENC != null
            && sessionENC.length > 0) {
            cgram = CryptoAPI.calcCryptogram(input, sessionENC);
        }

        if (cgram == null) {
            System.out.println("Error calcCryptogram");
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        return cgram;
    }

    public boolean setKeyIndex(int index, byte[] seq)
    {
        byte[] kEnc = null;
        byte[] kMac = null;
        byte[] kDek = null;

        if (index == (byte)0xFF) {
            kEnc = nxpDefaultKey;
            kMac = nxpDefaultKey;
            kDek = nxpDefaultKey;

        } else {
            try {
                kEnc = userKeys[index - 1].kEnc;
                kMac = userKeys[index - 1].kMac;
                kDek = userKeys[index - 1].kDek;

            } catch (java.lang.ArrayIndexOutOfBoundsException e) {
                return false;
            }
        }

        sessionENC
            = CryptoAPI.deriveSCP02SessionKey(kEnc, seq, CryptoAPI.constENC);
        sessionMAC
            = CryptoAPI.deriveSCP02SessionKey(kMac, seq, CryptoAPI.constMAC);
        sessionDEK
            = CryptoAPI.deriveSCP02SessionKey(kDek, seq, CryptoAPI.constDEK);

        System.out.println(String.format("%s chosen keys = %s / %s / %s",
                                         entity,
                                         _o.O_(kEnc),
                                         _o.O_(kMac),
                                         _o.O_(kDek)));
        System.out.println(String.format("%s session keys = %s / %s / %s",
                                         entity,
                                         _o.O_(sessionENC),
                                         _o.O_(sessionMAC),
                                         _o.O_(sessionDEK)));

        return true;
    }

    public SCP02(SCP02Keys[] keys)
    {
        this.icv = CryptoAPI.NullBytes8.clone();
        count++;

        // One for DummyIssuerSecurityDomain
        // One common for every IDPass applets
        Assert.assertTrue(count <= 2, "SCP02SecureChannel::constructor");
        this.userKeys = keys.clone();
        byte preferred = (byte)Helper.getRandomKvno(keys.length);
        keySetting[0] = preferred;
    }

    @Override public short processSecurity(APDU apdu) throws ISOException
    {
        // System.out.println(String.format("SCP02::processSecurity
        // [0x%02X]",securityLevel));
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        short responseLength = 0;

        switch (ins) {
        case INS_INITIALIZE_UPDATE:
            byte reqkvno = p1; // Get requested keyset#
            byte index = reqkvno;

            // Get host_challenge
            Util.arrayCopyNonAtomic(buffer,
                                    (short)ISO7816.OFFSET_CDATA,
                                    host_challenge,
                                    (short)0x00,
                                    (byte)host_challenge.length);

            // Card Specification V2.3.1 | GPC_SPE_034 (Mar 2018)
            // E.5.1.3 Reference Control Parameter P1 - Key Version Number
            if (reqkvno == 0x00) {
                index = keySetting[0];
            }

            SecureRandom random = new SecureRandom();
            byte[] cardrandom = new byte[6]; // card generates 6 random bytes
            random.nextBytes(cardrandom);
            byte[] seq = new byte[2];
            Util.setShort(seq, (short)0, sequenceCounter);

            card_challenge = Helper.arrayConcat(seq, cardrandom);

            byte[] hostcard_challenge
                = Helper.arrayConcat(host_challenge, card_challenge);

            if (setKeyIndex(index, seq) == false) {
                String info
                    = String.format("Command failed: No such key: %d/1", index);
                System.out.println(info);
                ISOException.throwIt((short)Helper.SW_KEY_NOT_FOUND);
            }

            byte[] hostcard_cryptogram = calcCryptogram(hostcard_challenge);
            _o.o_(hostcard_challenge, "hostcard_challenge");
            _o.o_(hostcard_cryptogram, "hostcard_cryptogram");

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try {
                // Prepare card response to offcard
                bos.write(diversification_data);
                bos.write(index);
                bos.write(keySetting[1]);
                bos.write(card_challenge);
                bos.write(hostcard_cryptogram);
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
            resetSecurity(); // clear security
            bInitUpdated = true;
            break;

        case ISO7816.INS_EXTERNAL_AUTHENTICATE:
            // 4 bytes command + 1 byte len + 8 bytes cgram = 13
            byte[] mdata = new byte[13];
            byte[] cryptogram = new byte[8];
            byte[] mac1 = new byte[8];

            Util.arrayCopyNonAtomic(
                buffer, (short)0, mdata, (short)0x00, (byte)mdata.length);

            Util.arrayCopyNonAtomic(buffer,
                                    (short)ISO7816.OFFSET_CDATA,
                                    cryptogram,
                                    (short)0x00,
                                    (byte)cryptogram.length);

            Util.arrayCopyNonAtomic(buffer,
                                    (short)(ISO7816.OFFSET_CDATA + 8),
                                    mac1,
                                    (short)0x00,
                                    (byte)mac1.length);

            byte[] mac2 = computeMac(mdata);

            boolean cryptogram_ok = false;
            boolean mac_ok = false;

            byte[] cardhost_challenge
                = Helper.arrayConcat(card_challenge, host_challenge);

            byte[] cardhost_cryptogram = calcCryptogram(cardhost_challenge);
            _o.o_(cardhost_challenge, "cardhost_challenge");
            _o.o_(cardhost_cryptogram, "cardhost_cryptogram");

            if (Arrays.equals(cryptogram, cardhost_cryptogram)) {
                cryptogram_ok = true;
            }

            if (Arrays.equals(mac1, mac2)) {
                mac_ok = true;
            }

            if (bInitUpdated == true && cryptogram_ok && mac_ok) {
                securityLevel = (byte)(securityLevel | p1 | AUTHENTICATED);
                bInitUpdated = false;
                responseLength = 0;
                sequenceCounter++;
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
        bInitUpdated = false;
        securityLevel = 0x00;
        this.icv = CryptoAPI.NullBytes8.clone();
    }

    @Override
    public short unwrap(byte[] buf, short arg1, short arg2) throws ISOException
    {
        short retval = arg2;
        byte[] decrypted = {};

        System.out.println("SCP02::unwrap");
        _o.o_(buf, arg2);
        short len = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);
        byte[] cmd = new byte[len];
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, cmd, (short)0, len);

        byte[] mactag = null;
        int datalen = len;

        if ((securityLevel & SCP02.C_MAC) != 0) {
            mactag = new byte[8];
            // Get MAC tag first.
            // Its verification is after decryption if encrypted
            Util.arrayCopyNonAtomic(cmd,
                                    (short)(cmd.length - 8),
                                    mactag,
                                    (short)0,
                                    (short)mactag.length);

            datalen = datalen - 8;
        }

        if (((securityLevel & SCP02.C_DECRYPTION) != 0) && datalen > 0) {
            byte[] encrypted = new byte[datalen];
            Util.arrayCopyNonAtomic(cmd,
                                    (short)0,
                                    encrypted,
                                    (short)0,
                                    (short)(datalen)); // don't copy mac tag

            _o.o_(encrypted, "encrypted");
            decrypted = CryptoAPI.decryptData(encrypted, sessionENC);
            _o.o_(decrypted, "decrypted");

            byte[] header = new byte[5];
            Util.arrayCopyNonAtomic(
                buf, (short)0, header, (short)0, (short)header.length);
            header[ISO7816.OFFSET_LC] = (byte)(8 + decrypted.length);
            byte[] combined = Helper.arrayConcat(header, decrypted);
            byte[] mComputed = computeMac(combined);
            Assert.assertEquals(mComputed, mactag, "MAC Tag mismatch");

            retval = Util.arrayCopyNonAtomic(decrypted,
                                             (short)0,
                                             buf,
                                             (short)ISO7816.OFFSET_CDATA,
                                             (short)decrypted.length);
        } else {
            byte[] headN = new byte[5]; // 4 bytes command apdu + 1 byte length
            Util.arrayCopyNonAtomic(
                buf, (short)0, headN, (short)0, (short)(headN.length));
            byte[] mComputed = computeMac(headN);
            _o.o_(mComputed, "mComputed");
            _o.o_(mactag, "mactag");
            Assert.assertEquals(mComputed, mactag, "MAC tag mismatch");
            headN[ISO7816.OFFSET_LC] = 0;

            retval
                = (short)(Util.arrayCopyNonAtomic(headN,
                                                  (short)0,
                                                  buf,
                                                  (short)ISO7816.OFFSET_CDATA,
                                                  (short)headN.length)
                          - headN.length);
        }

        return retval;
    }

    @Override
    public short wrap(byte[] buf, short arg1, short arg2)
        throws ArrayIndexOutOfBoundsException, ISOException
    {
        System.out.println("SCP02::wrap");
        return arg2;
    }

    @Override
    public short decryptData(byte[] buf, short arg1, short arg2)
        throws ISOException
    {
        System.out.println("SCP02::decryptData");
        return 0;
    }

    @Override
    public short encryptData(byte[] buf, short arg1, short arg2)
        throws ArrayIndexOutOfBoundsException
    {
        System.out.println("SCP02::encryptData");
        return 0;
    }

    @Override public byte getSecurityLevel()
    {
        // System.out.println(String.format("SCP02::securityLevel =
        // 0x%02X",securityLevel));
        return securityLevel;
    }
}

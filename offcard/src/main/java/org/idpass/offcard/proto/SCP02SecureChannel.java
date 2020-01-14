package org.idpass.offcard.proto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.idpass.offcard.misc.Helper;
import org.idpass.offcard.misc._o;
import org.testng.Assert;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import java.security.SecureRandom;
import java.util.Arrays;

public class SCP02SecureChannel implements org.globalplatform.SecureChannel
{
    public static final byte INITIALIZE_UPDATE = (byte)0x50;
    public static final byte EXTERNAL_AUTHENTICATE = (byte)0x82;
    public static final byte MAC = 0b0001;
    public static final byte ENC = 0b0010;

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

    private static final byte[] kvno_prot = {
        (byte)0xFF,
        (byte)0x02, // scp02
    };

    private static byte[] _icv = CryptoAPI.NullBytes8.clone();

    private byte[] kEnc = Hex.decode("404142434445464748494a4b4c4d4e4F");
    private byte[] kMac = Hex.decode("404142434445464748494a4b4c4d4e4F");
    private byte[] kDek = Hex.decode("404142434445464748494a4b4c4d4e4F");

    private byte[] sENC;
    private byte[] sMAC;
    private byte[] sDEK;

    private boolean bInitUpdated = false;
    private byte securityLevel = 0x00;

    private byte[] _card_challenge = new byte[8]; // Card generates this
    private byte[] _host_challenge = new byte[8]; // OffCard generates this
    private byte _kvno;

    //////////////////////////

    @Override public short processSecurity(APDU apdu) throws ISOException
    {
        short responseLength = 0;
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        // byte[] buffer = apdu.getBuffer();
        // byte[] buffer = apdu.getCurrentAPDUBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
        case INITIALIZE_UPDATE:
            _kvno = buffer[ISO7816.OFFSET_P1]; // requested keyset#

            SecureRandom random = new SecureRandom();
            byte[] cardrandom = new byte[6]; // card generates 6 random bytes
            random.nextBytes(cardrandom);
            byte[] scsc = new byte[2];
            Util.setShort(scsc, (short)0, secureChannelSequenceCounter);
            _card_challenge = Helper.arrayConcat(scsc, cardrandom);

            // Then card computes cryptogram
            // byte[] card_cryptogram = new byte[8];

            // Copy host_challenge
            Util.arrayCopyNonAtomic(buffer,
                                    (short)ISO7816.OFFSET_CDATA,
                                    _host_challenge,
                                    (short)0x00,
                                    (byte)8);

            sENC = CryptoAPI.deriveSCP02SessionKey(
                kEnc, scsc, CryptoAPI.constENC);
            sMAC = CryptoAPI.deriveSCP02SessionKey(
                kMac, scsc, CryptoAPI.constMAC);
            sDEK = CryptoAPI.deriveSCP02SessionKey(
                kDek, scsc, CryptoAPI.constDEK);

            // Compute sENC:
            // sENC =
            // des_ede_cbc(KEY,nullbytes8,scp02const_0182,card_challenge[0:2]);

            // Compute card_cryptogram:
            // card_cryptogram = des_ede_cbc(resize8(sENC),nullbytes8,
            // [host_challenge + card_challenge]);
            byte[] hostcard_challenge
                = Helper.arrayConcat(_host_challenge, _card_challenge);

            byte[] card_cryptogram
                = CryptoAPI.calcCryptogram(hostcard_challenge, sENC);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try {
                // Prepare card response to offcard
                bos.write(diversification_data);
                bos.write(kvno_prot);
                bos.write(_card_challenge);
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
                                    (byte)8);
            // Get mac
            byte[] mac = new byte[8];
            Util.arrayCopyNonAtomic(buffer,
                                    (short)(ISO7816.OFFSET_CDATA + 8),
                                    mac,
                                    (short)0x00,
                                    (byte)8);

            ///
            byte[] icv;
            if (Arrays.equals(_icv, CryptoAPI.NullBytes8)) {
                icv = _icv;
            } else {
                icv = CryptoAPI.updateIV(_icv, sMAC);
            }

            // compute mac here
            byte[] mcompute = CryptoAPI.computeMAC(mdata, icv, sMAC);

            // Because card has copy of card_challenge and host_challenge
            // previously at INITIALIZE_UPDATE, therefore card can also compute
            // the cryptogram and compare the received host_cryptogram here
            //
            // Also check if mac is correct
            boolean cryptogram_mac_correct = false;

            byte[] cardhost_challenge
                = Helper.arrayConcat(_card_challenge, _host_challenge);

            byte[] cgram = CryptoAPI.calcCryptogram(cardhost_challenge, sENC);

            Assert.assertEquals(cgram, host_cryptogram);

            if (Arrays.equals(mac, mcompute)
                && Arrays.equals(cgram, host_cryptogram)) {
                cryptogram_mac_correct = true;
            }

            if (bInitUpdated == true && cryptogram_mac_correct) {
                securityLevel = (byte)(securityLevel | buffer[2] | 0x80);
                bInitUpdated = false;
                responseLength = 0;
                secureChannelSequenceCounter++;
                // System.out.println("ACTIVE SECURITY LEVEL = " +
                // _o.formatBinary(securityLevel));
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
        if ((securityLevel & 0b0011) != 0) {
            if ((cla & 0x04) == 0) {
                resetSecurity();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        // System.out.println("SecureChannel::unwrap");
        //_o.o_(buf,arg2);
        return arg2;
    }

    @Override
    public short wrap(byte[] buf, short arg1, short arg2)
        throws ArrayIndexOutOfBoundsException, ISOException
    {
        byte cla = buf[ISO7816.OFFSET_CLA];
        if ((securityLevel & 0b0011) != 0) {
            if ((cla & 0x04) == 0) {
                resetSecurity();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        System.out.println("SecureChannel::wrap");
        _o.o_(buf, arg2);
        // 0x20 = 00100000 = R_ENCRYPTION
        // 0x10 = 00010000 = R_MAC
        return arg2; // TBD: Needs R_ENCRYPTION | R_MAC
    }

    @Override
    public short decryptData(byte[] buf, short arg1, short arg2)
        throws ISOException
    {
        byte cla = buf[ISO7816.OFFSET_CLA];
        if ((securityLevel & 0b0011) != 0) {
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
        if ((securityLevel & 0b0011) != 0) {
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
        // System.out.println("SecureChannel::getSecurityLevel = " +
        // _o.formatBinary(securityLevel));
        return securityLevel;
    }
}

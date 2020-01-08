package org.idpass.offcard.proto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;

import org.idpass.offcard.misc._o;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class SCP02SecureChannel implements org.globalplatform.SecureChannel
{
    static public final byte INITIALIZE_UPDATE = (byte)0x50;
    static public final byte EXTERNAL_AUTHENTICATE = (byte)0x82;
    static public final byte MAC = 0x01;
    static public final byte ENC = 0x02;

    private boolean bInitUpdate = false;
    private byte securityLevel = 0x00;

    // GlobalPlatform Card Specification 2.1.1
    // E.1.2 Entity Authentication
    private short secureChannelSequenceCounter = (short)0xBABE;

    private final byte[] kvno_prot = {
        (byte)0xFF,
        (byte)0x02, // scp02
    };
    private byte[] card_challenge = new byte[8]; // Card generates this
    private byte[] host_challenge = new byte[8]; // OffCard generates this
    private byte[] diversification_data = {
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

    @Override
    public short decryptData(byte[] arg0, short arg1, short arg2)
        throws ISOException
    {
        byte cla = arg0[ISO7816.OFFSET_CLA];
        if ((cla & 0x04) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
 
        System.out.println("SecureChannel::decryptData");
        return 0;
    }

    @Override
    public short encryptData(byte[] arg0, short arg1, short arg2)
        throws ArrayIndexOutOfBoundsException
    {
        byte cla = arg0[ISO7816.OFFSET_CLA];
        if ((cla & 0x04) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
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

    @Override public short processSecurity(APDU arg0) throws ISOException
    {
        short responseLength = 0;
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        int len = buffer[ISO7816.OFFSET_LC];
        byte[] data = new byte[len];

        Util.arrayCopyNonAtomic(
            buffer, (short)ISO7816.OFFSET_CDATA, data, (short)0x00, (byte)8);

        switch (ins) {
        case INITIALIZE_UPDATE:
            byte kvno = buffer[ISO7816.OFFSET_P1];
            /*
            System.out.println(
                "SecureChannel::processSecurity [INITIALIZE_UPDATE]");
            System.out.println(String.format("kvno=0x%02X",kvno));
            _o.o_("host_challenge",data);*/

            SecureRandom random = new SecureRandom();
            byte[] r = new byte[6]; // card generates 6 random bytes
            random.nextBytes(r);
            byte[] scsc = ByteBuffer.allocate(2)
                              .order(ByteOrder.BIG_ENDIAN)
                              .putShort(secureChannelSequenceCounter)
                              .array();
            System.arraycopy(scsc, 0, card_challenge, 0, 2); // 2 bytes counter
            System.arraycopy(r, 0, card_challenge, 2, r.length);

            // Then card computes cryptogram
            byte[] card_cryptogram = new byte[8];

            // Copy host_challenge
            Util.arrayCopyNonAtomic(buffer,
                                    (short)ISO7816.OFFSET_CDATA,
                                    host_challenge,
                                    (short)0x00,
                                    (byte)8);
            // Compute sENC:
            // sENC =
            // des_ede_cbc(KEY,nullbytes8,scp02const_0182,card_challenge[0:2]);

            // Compute card_cryptogram:
            // card_cryptogram = des_ede_cbc(resize8(sENC),nullbytes8,
            // [host_challenge + card_challenge]);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try {
                // Prepare card response to offcard
                bos.write(diversification_data);
                bos.write(kvno_prot);
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
            bInitUpdate = true;
            securityLevel = 0x00; // clear security
            break;

        case EXTERNAL_AUTHENTICATE:
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
            /*
            System.out.println(
                "SecureChannel::processSecurity [EXTERNAL_AUTHENTICATE]
            requesting SL of " + _o.formatBinary(sL));

            _o.o_("host_cryptogram",host_cryptogram);
            _o.o_("mac",mac);*/

            // Because card has copy of card_challenge and host_challenge
            // previously at INITIALIZE_UPDATE, therefore card can also compute
            // the cryptogram and compare the received host_cryptogram here
            //
            // Also check if mac is correct
            boolean cryptogram_mac_correct = true;

            if (bInitUpdate == true && cryptogram_mac_correct) {
                securityLevel = (byte)(securityLevel | buffer[2] | 0x80);
                bInitUpdate = false;
                responseLength = 0;
                secureChannelSequenceCounter++;
                // System.out.println("ACTIVE SECURITY LEVEL = " +
                // _o.formatBinary(securityLevel));
                break;
            } else {
                throw new IllegalStateException(
                    "Command failed: No previous initialize update");
            }
        }

        return responseLength;
    }

    @Override public void resetSecurity()
    {
        // System.out.println("SecureChannel::resetSecurity");
        securityLevel = 0x00;
    }

    @Override
    public short unwrap(byte[] arg0, short arg1, short arg2) throws ISOException
    {
        byte cla = arg0[ISO7816.OFFSET_CLA];
        if ((cla & 0x04) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // System.out.println("SecureChannel::unwrap");
        //_o.o_(arg0,arg2);
        return arg2;
    }

    @Override
    public short wrap(byte[] arg0, short arg1, short arg2)
        throws ArrayIndexOutOfBoundsException, ISOException
    {
        byte cla = arg0[ISO7816.OFFSET_CLA];
        if ((cla & 0x04) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        System.out.println("SecureChannel::wrap");
        _o.o_(arg0, arg2);
        // 0x20 = 00100000 = R_ENCRYPTION
        // 0x10 = 00010000 = R_MAC
        return arg2; // TBD: Needs R_ENCRYPTION | R_MAC
    }
}

package org.idpass.dev;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

/*
This is a stand-alone small scale replica of IdpassApplet. It will be used to
diagnose unusual issues or to probe a card's internal state:
    - memory
    - security level
*/
public class DecodeApplet extends Applet implements ExtendedLength, AppletEvent
{
    private static final byte INS_NOOP = (byte)0x00;
    private static final byte INS_ECHO = (byte)0x01;
    private static final byte INS_CONTROL = (byte)0x02;

    public final static class Utils
    {
        public static final byte BYTE_00 = (byte)0x00;
        public static final short SHORT_00 = (short)0x0000;

        // Call JCSystem.requestObjectDeletion if Supported
        public static void requestObjectDeletion()
        {
            if (JCSystem.isObjectDeletionSupported()) {
                JCSystem.requestObjectDeletion();
            }
        }

        private Utils()
        {
        }
    }

    public final static short LENGTH_APDU_EXTENDED = (short)0x7FFF;
    private static final byte INS_INITIALIZE_UPDATE = (byte)0x50;
    private static final byte INS_BEGIN_RMAC_SESSION = (byte)0x7A;
    private static final byte INS_END_RMAC_SESSION = (byte)0x78;

    protected static final byte MASK_GP = (byte)0x80;
    protected static final byte MASK_SECURED = (byte)0x0C;

    private byte[] apduData;
    protected byte cla;
    protected byte ins;
    protected byte p1;
    protected byte p2;

    protected SecureChannel secureChannel;

    private byte control;
    private byte[] m_memo;

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        DecodeApplet applet = new DecodeApplet(bArray, bOffset, bLength);

        // GP-compliant JavaCard applet registration
        applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    protected DecodeApplet(byte[] bArray, short bOffset, byte bLength)
    {
        byte lengthAID = bArray[bOffset];
        short offsetAID = (short)(bOffset + 1);
        short offset = bOffset;
        offset += (bArray[offset]); // skip aid
        offset++;
        offset += (bArray[offset]); // skip privileges
        offset++;

        // read params
        short lengthIn = bArray[offset];
        if (lengthIn != 0) {
            this.control = bArray[(short)(offset + 1)];
        }
    }

    @Override public void uninstall()
    {
        apduData = null;
    }

    @Override public void process(APDU apdu) throws ISOException
    {
        try {
            byte[] buffer = apdu.getBuffer();
            cla = buffer[ISO7816.OFFSET_CLA];
            ins = buffer[ISO7816.OFFSET_INS];
            p1 = buffer[ISO7816.OFFSET_P1];
            p2 = buffer[ISO7816.OFFSET_P2];

            // ISO class
            if ((cla & (~MASK_SECURED)) == ISO7816.CLA_ISO7816) {
                if (ins == ISO7816.INS_SELECT) {
                    processSelect();
                    return;
                }
            }

            switch (ins) {
            case INS_INITIALIZE_UPDATE:
            case ISO7816.INS_EXTERNAL_AUTHENTICATE:
            case INS_BEGIN_RMAC_SESSION:
            case INS_END_RMAC_SESSION:
                checkClaIsGp();
                // allow to make contactless SCP
                // checkProtocolContacted();
                processSecurity();
                break;
            default:
                processInternal(apdu);
            }

        } finally {
            if (apduData != null) {
                apduData = null;
                Utils.requestObjectDeletion();
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    public boolean select()
    {
        secureChannel = GPSystem.getSecureChannel();
        return true;
    }

    public void deselect()
    {
        // free the handle of the Security Domain associated with this applet.
        secureChannel.resetSecurity();
    }

    void processSelect()
    {
        if (!selectingApplet()) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        setIncomingAndReceiveUnwrap();

        byte[] buffer = getApduData();

        // short length = Util.setShort(buffer, Utils.SHORT_00,
        // personasRepository.getPersonasCount());
        // setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }

    protected void processSecurity()
    {
        // send to ISD
        short responseLength
            = secureChannel.processSecurity(APDU.getCurrentAPDU());
        if (responseLength != 0) {
            APDU.getCurrentAPDU().setOutgoingAndSend(
                (short)ISO7816.OFFSET_CDATA, responseLength);
        }
    }

    protected void checkClaIsGp()
    {
        if ((cla & MASK_GP) != MASK_GP) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    protected void processInternal(APDU apdu) throws ISOException
    {
        switch (this.ins) {
        case INS_NOOP:
            ins_noop(apdu);
            break;
        case INS_ECHO:
            ins_echo(apdu);
            break;
        case INS_CONTROL:
            ins_control(apdu);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    protected byte[] getApduData()
    {
        if (APDU.getCurrentAPDU().getCurrentState()
            < APDU.STATE_PARTIAL_INCOMING) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        if (apduData == null) {
            return APDU.getCurrentAPDUBuffer();
        } else {
            return apduData;
        }
    }

    protected short setIncomingAndReceiveUnwrap()
    {
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        short bytesRead = APDU.getCurrentAPDU().setIncomingAndReceive();
        short apduDataOffset = APDU.getCurrentAPDU().getOffsetCdata();
        boolean isExtendedLengthData
            = apduDataOffset == ISO7816.OFFSET_EXT_CDATA;
        short overallLength = APDU.getCurrentAPDU().getIncomingLength();

        if (isExtendedLengthData) {
            apduData = new byte[LENGTH_APDU_EXTENDED];

            Util.arrayCopyNonAtomic(buffer,
                                    (short)0,
                                    apduData,
                                    (short)0,
                                    (short)(apduDataOffset + bytesRead));

            if (bytesRead != overallLength) { // otherwise we're finished, all
                                              // bytes received
                short received = 0;
                do {
                    received = APDU.getCurrentAPDU().receiveBytes((short)0);
                    Util.arrayCopyNonAtomic(buffer,
                                            (short)0,
                                            apduData,
                                            (short)(apduDataOffset + bytesRead),
                                            received);
                    bytesRead += received;
                } while (!(received == 0 || bytesRead == overallLength));
            }

            buffer = apduData;
        }

        short result = overallLength;

        byte sl = secureChannel.getSecurityLevel();
        if ((sl & SecureChannel.C_DECRYPTION) != 0
            || (sl & SecureChannel.C_MAC) != 0) {
            result = (short)(secureChannel.unwrap(
                                 buffer,
                                 (short)0,
                                 (short)(apduDataOffset + overallLength))
                             - apduDataOffset);
        }

        Util.arrayCopyNonAtomic(
            buffer, apduDataOffset, buffer, (short)0, result);

        short bytesLeft = (short)(apduDataOffset - result);
        if (bytesLeft > 0) {
            Util.arrayFillNonAtomic(buffer,
                                    (short)(apduDataOffset - bytesLeft),
                                    bytesLeft,
                                    (byte)0);
        }
        return result;
    }

    protected void setOutgoingAndSendWrap(byte[] buffer, short bOff, short len)
    {
        if (APDU.getCurrentAPDU().getCurrentState() < APDU.STATE_OUTGOING) {
            APDU.getCurrentAPDU().setOutgoing();
        }

        byte sl = secureChannel.getSecurityLevel();

        if ((sl & SecureChannel.R_ENCRYPTION) != 0
            || (sl & SecureChannel.R_MAC) != 0) {
            len = secureChannel.wrap(buffer, bOff, len);
        }

        APDU.getCurrentAPDU().setOutgoingLength(len);
        APDU.getCurrentAPDU().sendBytesLong(buffer, bOff, len);
    }
    ////////////////////////////////////////////////////////////////////////////
    protected SecureChannel getSecurityObject()
    {
        return secureChannel;
    }

    protected boolean isCheckC_MAC()
    {
        byte sl = secureChannel.getSecurityLevel();

        if ((cla & MASK_SECURED) > 0) {
            if (((sl & SecureChannel.AUTHENTICATED) == 0)
                || ((sl & SecureChannel.C_MAC) == 0)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return true;
        } else {
            if ((sl & SecureChannel.AUTHENTICATED) != 0) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return false;
        }
    }

    protected boolean isCheckC_DECRYPTION()
    {
        byte sl = secureChannel.getSecurityLevel();

        if ((cla & MASK_SECURED) > 0) {
            if (((sl & SecureChannel.AUTHENTICATED) == 0)
                || ((sl & SecureChannel.C_DECRYPTION) == 0)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return true;
        } else {
            if ((sl & SecureChannel.AUTHENTICATED) != 0) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return false;
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    public void ins_noop(APDU apdu)
    {
    }

    public void ins_echo(APDU apdu)
    {
        if ((control & 0x01) != 0) {
            if (!(isCheckC_MAC())) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }

        if ((control & 0x02) != 0) {
            if (!(isCheckC_DECRYPTION())) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }

        short lc = setIncomingAndReceiveUnwrap();
        byte[] buffer = getApduData();

        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, lc);
    }

    public void ins_control(APDU apdu)
    {
        control = p1;
    }
}

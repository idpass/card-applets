package org.idpass.offcard.misc;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

import org.idpass.offcard.proto.SCP02;
// import org.testng.Assert;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;

import javacard.framework.Util;

import org.globalplatform.SecureChannel;

// clang-format off

public class Helper
{
    public static final String SHORT_UUID_BASE = "000000000000000000DEC0DE";
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static Invariant Assert = new Invariant(true);
    
    public static CardSimulator simulator;
    public static CardChannel channel;

    public static final byte[] SW9000 = new byte[] {(byte)0x90, (byte)0x00};
    public static final byte[] SW9100 = new byte[] {(byte)0x91, (byte)0x00};
    public static final byte[] SW6A88 = new byte[] {(byte)0x6A, (byte)0x88}; // Reference data not found
    public static final byte[] SW6985 = new byte[] {(byte)0x69, (byte)0x85};
    public static final byte[] SW6999 = new byte[] {(byte)0x69, (byte)0x99}; // SW_APPLET_SELECT_FAILED
    public static final byte[] SW6701 = new byte[] {(byte)0x67, (byte)0x01};

    public static final int SW_NO_ERROR             = 0x9000;
    public static final int SW_NO_PRECISE_DIAGNOSIS = 0x6F00;
    public static final int SW_KEY_NOT_FOUND        = 0x6A88;
    public static final int SW_RECORD_NOT_FOUND     = 0x6A83;
    public static final int SW_VERIFICATION_FAILED  = 0x6300;

    private static Random ran = new Random();

    public enum Mode { SIM, PHY }
    // clang-format on

    public static void reInitialize()
    {
        channel = null;
        simulator = null;
    }

    public static String printsL(byte sL)
    {
        String s = "";

        if (sL == SecureChannel.NO_SECURITY_LEVEL) {
            s = "NO_SECURITY_LEVEL";
        }

        if ((sL & SecureChannel.C_MAC) != 0) {
            s = s + "C_MAC";
        }

        if ((sL & SecureChannel.C_DECRYPTION) != 0) {
            s = s + "|C_DECRYPTION";
        }

        if ((sL & SecureChannel.R_MAC) != 0) {
            s = s + "|R_MAC";
        }

        if ((sL & SecureChannel.R_ENCRYPTION) != 0) {
            s = s + "|C_ENCRYPTION";
        }

        if ((sL & SCP02.ANY_AUTHENTICATED) != 0) {
            s = s + "|ANY_AUTHENTICATED";
        }

        if ((sL & SecureChannel.AUTHENTICATED) != 0) {
            s = s + "|AUTHENTICATED";
        }

        return s;
    }

    // Kvno =  Key Version Number as termed in the spec
    // This method simulates the card defaulting to
    // different kvno. Since 0xFF is a valid
    // kvno to mean an NXP factory default key, that value
    // is also included. If a list has 5 elements, this
    // method randomly returns any of: 1 to 5 inclusive, 0xFF
    public static int getRandomKvno(int n)
    {
        int lower = 1;
        int upper = lower + n - 1;
        int r = ran.nextInt(upper + 1)
                + lower; // between lower and upper inclusive or 0xFF
        if (r > upper) {
            r = 0xFF;
        }
        return r;
    }

    public static String print(byte[] bytes)
    {
        int n = 0;
        StringBuilder sb = new StringBuilder();
        sb.append("\n");
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
            n++;
            if (n % 32 == 0) {
                sb.append("\n");
            }
        }
        return sb.toString();
    }

    public static byte[] arrayConcat(byte[] arr1, byte[] arr2)
    {
        byte[] arr1arr2 = new byte[arr1.length + arr2.length];
        System.arraycopy(arr1, 0, arr1arr2, 0, arr1.length);
        System.arraycopy(arr2, 0, arr1arr2, arr1.length, arr2.length);
        return arr1arr2;
    }

    public static CardChannel getPcscChannel() // throws CardException
    {
        if (channel != null) {
            return channel;
        }

        TerminalFactory factory = TerminalFactory.getDefault();

        try {
            CardTerminals terms = factory.terminals();
            if (terms != null) {
                List<CardTerminal> terminals = terms.list();
                int n = terminals.size();
                if (n == 2) {
                    CardTerminal terminal = terminals.get(1);
                    Card card = null;
                    card = terminal.connect("*");
                    channel = card.getBasicChannel();
                }
            }
        } catch (CardException e) {
            System.out.println(e.getCause());
        } catch (IndexOutOfBoundsException e) {
            System.out.println(e.getCause());
        }

        return channel;
    }

    public static CardChannel getjcardsimChannel() throws CardException
    {
        if (channel != null) {
            return channel;
        }

        simulator = new CardSimulator();
        CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
        Card card = terminal.connect("T=1");
        channel = card.getBasicChannel();
        return channel;
    }

    public static boolean checkstatus(byte[] byteseq)
    {
        byte[] status = new byte[2];
        if (byteseq.length < 2) {
            return false;
        }
        Util.arrayCopyNonAtomic(byteseq,
                                (short)(byteseq.length - 2),
                                status,
                                (short)0,
                                (short)status.length);
        return java.util.Arrays.equals(status, Helper.SW9000);
    }

    public static String bytesToHex(byte[] bytes)
    {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    
    public static byte[] getASCIIBytes(String str)
    {
        try {
            return str.getBytes("US-ASCII");
        } catch (IllegalArgumentException e) {
            return str.getBytes();
        } catch (UnsupportedEncodingException e) {
            return str.getBytes();
        }
    }
    
    public static byte[] clone(byte[] value)
    {
        if (value == null) {
            return null;
        }
        int length = ((byte[])value).length;
        byte[] bClone = new byte[length];
        System.arraycopy(value, 0, bClone, 0, length);
        return bClone;
    }

    public static long UUIDTo32Bit(UUID uuid)
    {
        if (uuid == null) {
            return -1;
        }
        String str = uuid.toString().toUpperCase();
        int shortIdx = str.indexOf(SHORT_UUID_BASE);
        if ((shortIdx != -1)
            && (shortIdx + SHORT_UUID_BASE.length() == str.length())) {
            // This is short 16-bit or 32-bit UUID
            return Long.parseLong(str.substring(0, shortIdx), 16);
        }
        return -1;
    }
    
    public static byte[] UUIDToByteArray(String uuidStringValue)
    {
        byte[] uuidValue = new byte[16];
        if (uuidStringValue.indexOf('-') != -1) {
            /*
            throw new NumberFormatException(
                "The '-' character is not allowed in UUID: " + uuidStringValue);*/
            uuidStringValue = uuidStringValue.replaceAll("[\\s\\-()]", "");
        }
        for (int i = 0; i < 16; i++) {
            uuidValue[i] = (byte)Integer.parseInt(
                uuidStringValue.substring(i * 2, i * 2 + 2), 16);
        }
        return uuidValue;
    }

    public static byte[] UUIDToByteArray(final UUID uuid)
    {
        return UUIDToByteArray(uuid.toString());
    }

    public static String newStringUTF8(byte bytes[])
    {
        try {
            return new String(bytes, "UTF-8");
        } catch (IllegalArgumentException e) {
            return new String(bytes);
        } catch (UnsupportedEncodingException e) {
            return new String(bytes);
        }
    }
    
    public static String newStringASCII(byte bytes[])
    {
        try {
            return new String(bytes, "US-ASCII");
        } catch (IllegalArgumentException e) {
            return new String(bytes);
        } catch (UnsupportedEncodingException e) {
            return new String(bytes);
        }
    }
    
    public static String toHexString(long l)
    {
        StringBuffer buf = new StringBuffer();
        String lo = Integer.toHexString((int)l);
        if (l > 0xffffffffl) {
            String hi = Integer.toHexString((int)(l >> 32));
            buf.append(hi);
            for (int i = lo.length(); i < 8; i++) {
                buf.append('0');
            }
        }
        buf.append(lo);
        return buf.toString();
    }
    
    public static String UUIDByteArrayToString(byte[] uuidValue)
    {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < uuidValue.length; i++) {
            buf.append(Integer.toHexString(uuidValue[i] >> 4 & 0xf));
            buf.append(Integer.toHexString(uuidValue[i] & 0xf));
        }
        return buf.toString();
    }
}

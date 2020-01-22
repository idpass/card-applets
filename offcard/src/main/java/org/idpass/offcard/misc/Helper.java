package org.idpass.offcard.misc;

import java.util.List;
import java.util.Random;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import org.idpass.offcard.proto.SCP02;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;

import javacard.framework.Util;

import org.globalplatform.SecureChannel;

// clang-format off

public class Helper
{
    public static CardSimulator simulator;
    public static CardChannel channel;

    public static final byte[] SW9000 = new byte[] {(byte)0x90, (byte)0x00};
    public static final byte[] SW9100 = new byte[] {(byte)0x91, (byte)0x00};
    public static final byte[] SW6A88 = new byte[] {(byte)0x6A, (byte)0x88}; // Reference data not found
    public static final byte[] SW6985 = new byte[] {(byte)0x69, (byte)0x85};

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
            List<CardTerminal> terminals = factory.terminals().list();
            CardTerminal terminal = terminals.get(1);
            Card card = null;
            card = terminal.connect("*");
            channel = card.getBasicChannel();
        } catch (CardException e) {
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
}

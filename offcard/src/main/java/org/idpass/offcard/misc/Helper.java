package org.idpass.offcard.misc;

import java.util.List;
import java.util.Random;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import org.bouncycastle.util.encoders.Hex;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;

public class Helper
{
    public static CardSimulator simulator;

    public static final byte[] SW9000 = new byte[] {(byte)0x90, (byte)0x00};
    public static final byte[] SW9100 = new byte[] {(byte)0x91, (byte)0x00};
    public static final byte[] SW6A88
        = new byte[] {(byte)0x6A, (byte)0x88}; // Reference data not found

    public static final int SW_NO_ERROR             = 0x9000;
    public static final int SW_NO_PRECISE_DIAGNOSIS = 0x6F00;
    public static final int SW_KEY_NOT_FOUND        = 0x6A88;
    public static final int SW_RECORD_NOT_FOUND     = 0x6A83;

    public static final byte[] nxpDefaultKey
        = Hex.decode("404142434445464748494a4b4c4d4e4F");

    public abstract class GP
    {
        public static final byte AUTHENTICATED      = (byte)0b10000000;
        public static final byte C_DECRYPTION       = (byte)0b00000010;
        public static final byte C_MAC              = (byte)0b00000001;
        public static final byte R_ENCRYPTION       = (byte)0b00100000;
        public static final byte R_MAC              = (byte)0b00010000;
        public static final byte NO_SECURITY_LEVEL  = (byte)0b00000000;
    }

    private static Random ran = new Random();

    public enum Mode { SIM, PHY }

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
            sb.append(String.format("%02X", b));
            n++;
            if (n % 64 == 0) {
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

    public static CardChannel getPcscChannel()
    {
        TerminalFactory factory = TerminalFactory.getDefault();
        try {
            List<CardTerminal> terminals = factory.terminals().list();
            CardTerminal terminal = terminals.get(1);
            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();
            return channel;
        } catch (javax.smartcardio.CardException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static CardChannel getjcardsimChannel()
    {
        simulator = new CardSimulator();
        CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
        try {
            Card card = terminal.connect("T=1");
            CardChannel channel = card.getBasicChannel();
            return channel;
        } catch (javax.smartcardio.CardException e) {
            e.printStackTrace();
            System.exit(1);
        }

        return null;
    }
}

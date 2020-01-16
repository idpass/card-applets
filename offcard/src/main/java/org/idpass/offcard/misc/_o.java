package org.idpass.offcard.misc;

public class _o
{
    public static void o_(String title, byte[] msg, int len)
    {
        System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println(title);
        o_(msg, len);
        System.out.println("-------------------------------------------------");
    }

    public static void o_(byte[] msg, int len)
    {
        for (int j = 1; j < len + 1; j++) {
            if (j % 32 == 1 || j == 0) {
                if (j != 0) {
                    System.out.println();
                }
                System.out.format("0%d\t|\t", j / 8);
            }
            System.out.format("%02X", msg[j - 1]);
            if (j % 8 == 0) {
                System.out.print(" ");
            }
        }
        System.out.println();
    }

    public static void o_(byte[] msg, String title)
    {
        o_(title, msg);
    }

    public static void o_(String title, byte[] msg)
    {
        System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println(title);
        o_(msg);
        System.out.println("-------------------------------------------------");
    }

    public static void o_(byte[] msg)
    {
        for (int j = 1; j < msg.length + 1; j++) {
            if (j % 32 == 1 || j == 0) {
                if (j != 0) {
                    System.out.println();
                }
                System.out.format("0%d\t|\t", j / 8);
            }
            System.out.format("%02X", msg[j - 1]);
            if (j % 8 == 0) {
                System.out.print(" ");
            }
        }
        System.out.println();
    }

    public static String formatBinary(byte b)
    {
        String s = String.format("%8s", Integer.toBinaryString(b & 0xFF))
                       .replace(' ', '0');
        return s;
    }
}
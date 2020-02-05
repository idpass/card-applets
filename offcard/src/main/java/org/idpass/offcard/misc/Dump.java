package org.idpass.offcard.misc;

import java.util.Scanner;

public class Dump
{
    static Scanner stdin = new Scanner(System.in);

    public static void print(String title, byte[] msg, int len)
    {
        System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println(title);
        print(msg, len);
        System.out.println("-------------------------------------------------");
    }

    public static void print(byte[] msg, int len)
    {
        if (msg == null)
            return;

        for (int j = 1; j < len + 1; j++) {
            if (j % 32 == 1 || j == 0) {
                if (j != 0) {
                    System.out.println();
                }
                // System.out.format("0%d\t|\t", j / 8);
            }
            System.out.format("%02X", msg[j - 1]);
            if (j % 4 == 0) {
                System.out.print(" ");
            }
        }
        System.out.println();
    }

    public static void print(byte[] msg, String title)
    {
        print(title, msg);
    }

    public static void print(String title, byte[] msg)
    {
        System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println(title);
        print(msg);
        System.out.println("-------------------------------------------------");
    }

    public static void print(byte[] msg)
    {
        if (msg == null)
            return;

        for (int j = 1; j < msg.length + 1; j++) {
            if (j % 32 == 1 || j == 0) {
                if (j != 0) {
                    System.out.println();
                }
                // System.out.format("0%d\t|\t", j / 8);
            }
            System.out.format("%02X", msg[j - 1]);
            if (j % 4 == 0) {
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

    public static String printline(byte[] bytes, String title)
    {
        if (title != null)
            System.out.print(String.format("%s = ", title));
        int n = 0;
        StringBuilder sb = new StringBuilder();
        // sb.append("\n");
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
            if (title != null)
                System.out.print(String.format("%02X", b));
            n++;
            /*if (n % 128 == 0) {
                sb.append("\n");
                if (title!=null) System.out.println();
            }*/
        }
        if (title != null)
            System.out.println();
        return sb.toString();
    }

    public static String input(String msg)
    {
        System.out.println(msg);
        return stdin.next();
    }
}

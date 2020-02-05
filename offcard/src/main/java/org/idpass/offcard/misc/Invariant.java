package org.idpass.offcard.misc;

import org.testng.asserts.IAssert;
import org.testng.asserts.SoftAssert;

// This is a soft Assert object that prints if
// an assertion fails but continues execution
public class Invariant extends SoftAssert
{
    private boolean iflag = false; // for local control
    private boolean cflag = false; // for global control
    private static int errorCount;

    public static boolean check()
    {
        if (errorCount != 0) {
            System.out.println("*** Invariant errorCount = " + errorCount
                               + " ***");
        } else
            System.out.println("--- Invariant OK ---");
        return errorCount == 0;
    }

    public Invariant(boolean flag)
    {
        cflag = System.getProperty("xxx") != null ? true : false;
        this.iflag = flag;
    }

    public Invariant()
    {
        cflag = System.getProperty("xxx") != null ? true : false;
        iflag = false;
    }

    @Override
    public void onAssertFailure(IAssert<?> assertCommand, AssertionError ex)
    {
        errorCount++;

        String m = ex.getMessage();
        int idx = m.indexOf("expected");

        Object expected = assertCommand.getExpected();
        Object actual = assertCommand.getActual();
        String title = m.substring(0, idx);
        String msg = String.format("AssertionError@( %s) ", title);

        String exp = "?";
        String act = "?";

        if (expected instanceof Integer || expected instanceof Byte
            || expected instanceof Short) {
            exp = String.format("0x%04X",
                                Integer.parseInt(expected.toString()));
            act = String.format("0x%04X", Integer.parseInt(actual.toString()));
            System.out.println(
                String.format("%s expecting %s, got %s", msg, exp, act));
        } else if (expected instanceof byte[]) {
            byte[] exp_bytes = (byte[])expected;
            byte[] act_bytes = (byte[])actual;
            System.out.println(ex.getMessage());
            Dump.print("Expected bytes:", exp_bytes);
            Dump.print("Received bytes:", act_bytes);
        } else {
            if (expected != null) {
                exp = expected.toString();
            }
            if (actual != null) {
                act = actual.toString();
            }

            System.out.println(
                String.format("%s expecting object %s, got %s", msg, exp, act));
        }

        if (iflag || cflag) {
            // throw new AssertionError(msg);
            throw new IllegalStateException(msg);
        }
    }
}

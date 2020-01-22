package org.idpass.offcard.misc;

import org.testng.asserts.IAssert;
import org.testng.asserts.SoftAssert;

// This is a soft Assert object that prints if
// an assertion fails but continues execution
public class Invariant extends SoftAssert
{
    public static boolean cflag = false; // for global control
    public boolean iflag = false; // for local control
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
        this.iflag = flag;
    }

    public Invariant()
    {
        cflag = false;
        iflag = false;
    }

    @Override
    public void onAssertFailure(IAssert<?> assertCommand, AssertionError ex)
    {
        errorCount++;

        Object expected = assertCommand.getExpected();
        Object actual = assertCommand.getActual();
        String msg = "AssertionError@" + ex.getMessage().split(" ", 2)[0] + " ";

        if (expected instanceof Integer || expected instanceof Byte
            || expected instanceof Short) {
            msg = msg
                  + String.format("0x%04X",
                                  Integer.parseInt(expected.toString()))
                  + " "
                  + String.format("0x%04X",
                                  Integer.parseInt(actual.toString()));
            System.out.println(msg);
        } else if (expected instanceof byte[]) {
            byte[] exp_bytes = (byte[])expected;
            byte[] act_bytes = (byte[])actual;
            System.out.println(ex.getMessage());
            _o.o_("Expected bytes", exp_bytes);
            _o.o_("Got bytes", act_bytes);
        } else {
            if (expected != null) {
                msg = msg + expected.toString();
            }
            if (actual != null) {
                msg = msg + " " + actual.toString();
            }
            System.out.println(msg);
        }

        if (iflag || cflag) {
            // throw new AssertionError(msg);
            throw new IllegalStateException(msg);
        }
    }
}

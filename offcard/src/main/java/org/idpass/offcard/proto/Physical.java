package org.idpass.offcard.proto;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException; //@dup1@
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import javacard.framework.AID;
import javacard.framework.Applet;
// import javacard.framework.CardException; //@dup1_@
import javacard.framework.ISOException;
import javacard.framework.SystemException;

public class Physical
{
    private CardChannel channel;

    public Physical(CardChannel channel)
    {
        this.channel = channel;
    }

    public int loadCAPFile(String capFile)
    {
        return 0;
    }

    // This method is to appease mirror object instance so that
    // unification code is achieved between physical and simulator 
    public AID installApplet(AID aid,
                             Class<? extends Applet> appletClass,
                             byte bArray[],
                             short bOffset,
                             byte bLength) throws SystemException
    {
        Method initMethod;

        try {
            initMethod = appletClass.getMethod(
                "install", new Class[] {byte[].class, short.class, byte.class});
        } catch (NoSuchMethodException e) {
            throw new IllegalArgumentException(
                "Class does not provide install method");
        }

        try {
            initMethod.invoke(null, bArray, (short)0, (byte)bArray.length);
        } catch (InvocationTargetException e) {
            try {
                ISOException isoException = (ISOException)e.getCause();
                throw isoException;
            } catch (ClassCastException cce) {
                throw new SystemException(SystemException.ILLEGAL_AID);
            }
        } catch (Exception e) {
            throw new SystemException(SystemException.ILLEGAL_AID);
        }

        return aid;
    }

    public byte[] selectAppletWithResult(byte[] id_bytes) throws SystemException
    {
        byte[] result = {(byte)0x6A, (byte)0xA2};
        ResponseAPDU response = null;
        CommandAPDU command = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, id_bytes);
        response = Transmit(command);
        result = response.getBytes();
        return result;
    }

    public ResponseAPDU Transmit(CommandAPDU apdu)
    {
        ResponseAPDU response = null;

        try {
            response = channel.transmit(apdu);
        } catch (CardException e) {
            e.printStackTrace();
        }

        if (response.getSW() != 0x9000) {
            System.out.println("ERROR: "
                               + String.format(" 0x%04x", response.getSW()));
        }

        return response;
    }

}


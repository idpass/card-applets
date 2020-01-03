package org.idpass.offcard.misc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;

public class Params
{
    public String id_String;
    public byte[] id_bytes;
    public AID id_AID;

    private byte[] privileges;
    private byte[] installParams;
    private byte[] bArray = null;

    public Params(String appletInstanceAID,
                  byte[] privileges,
                  byte[] installParams)
    {
        id_String = appletInstanceAID;
        id_bytes = Hex.decode(id_String);
        id_AID = AIDUtil.create(id_bytes);

        this.privileges = privileges;
        this.installParams = installParams;
    }

    public short getOffset()
    {
        return (short)0x0000;
    }

    public byte getLength()
    {
        byte len = (byte)bArray.length;
        return len;
    }

    public byte[] getArray()
    {
        if (bArray != null) {
            return bArray;
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(id_bytes.length);
            bos.write(id_bytes);
            bos.write(privileges.length);
            if (privileges.length > 0) {
                bos.write(privileges);
            }
            bos.write(installParams.length);
            if (installParams.length > 0) {
                bos.write(installParams);
            }
            bArray = bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return bArray;
    }
}

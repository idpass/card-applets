package org.idpass.offcard.proto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Vector;
import java.util.UUID;

import org.idpass.offcard.misc.Helper;

// clang-format off
/*------------------+-----------------------------------------------+
|                   | Valid           |                             |
| Type Descriptor   | Size Descriptor | Description                 |
|---|---|---|---|---|-----------------|-----------------------------|
| 0 | 0 | 0 | 0 | 0 |  0              | Nil. The special null type  |
|---|---|---|---|---|-----------------|-----------------------------|
| 0 | 0 | 0 | 0 | 1 |  0,1,2,3,4      | Unsigned integer            |
|---|---|---|---|---|-----------------|-----------------------------|
| 0 | 0 | 0 | 1 | 0 |  0,1,2,3,4      | Signed 2s complement integer|
|---|---|---|---|---|-----------------|-----------------------------|
| 0 | 0 | 0 | 1 | 1 |  1,2,4          | UUID                        |
|---|---|---|---|---|-----------------|-----------------------------|
| 0 | 0 | 1 | 0 | 0 |  5,6,7          | Text string                 |
|---|---|---|---|---|-----------------|-----------------------------|
| 0 | 0 | 1 | 0 | 1 |  0              | Boolean                     |
|---|---|---|---|---|-----------------|-----------------------------| 
| 0 | 0 | 1 | 1 | 0 |  5,6,7          | Data Element Sequence       |
|---|---|---|---|---|-----------------|-----------------------------| 
| 0 | 0 | 1 | 1 | 1 |  5,6,7          | Data Element Alternative    |
|---|---|---|---|---|-----------------|-----------------------------| 
| 0 | 1 | 0 | 0 | 0 |  5,6,7          | URI, uniform resource loc   |
|---|---|---|---|---|-----------------|-----------------------------| 
| 0 | 1 | 0 | 0 | 1 |  5,6,7          | Generic byte sequence       |
|-------------------|-----------------|-----------------------------| 
| 10-31             |                 | Reserved                    |
|----------------------------------------------------------------- */


/*----------+-------------------------------------------------------+
|           |                 |                                     |
| Size Index| Additional bits | Data size                           |
|---|---|---|-----------------|-------------------------------------|
| 0 | 0 | 0 |      0          | 1 byte. Exception if data element is| 
|   |   |   |                 | nil then the data size is 0 byte    |
|---|---|---|-----------------|-------------------------------------|
| 0 | 0 | 1 |      0          | 2 bytes                             |
|---|---|---|-----------------|-------------------------------------|
| 0 | 1 | 0 |      0          | 4 bytes                             |
|---|---|---|-----------------|-------------------------------------|
| 0 | 1 | 1 |      0          | 8 bytes                             |
|---|---|---|-----------------|-------------------------------------|
| 1 | 0 | 0 |      0          | 16 bytes                            |
|---|---|---|-----------------|-------------------------------------|
| 1 | 0 | 1 |      8          | The data size is contained in the   |
|   |   |   |                 | additional 8 bits as unsigned int   |    
|---|---|---|-----------------|-------------------------------------| 
| 1 | 1 | 0 |      16         | The data size is contained in the   |
|   |   |   |                 | additional 16 bits as unsigned int  |     
|---|---|---|-----------------|-------------------------------------| 
| 1 | 1 | 1 |      32         | The data size is contained in the   |
|   |   |   |                 | additional 32 bits as usgigned int  |     
|------------------------------------------------------------------ */
// clang-format on

public class DataElement
{
    public static final short NULL = 0x0000;
    public static final short U_INT_1 = 0x0008;
    public static final short U_INT_2 = 0x0009;
    public static final short U_INT_4 = 0x000A;
    public static final short U_INT_8 = 0x000B;
    public static final short U_INT_16 = 0x000C;
    public static final short INT_1 = 0x0010;
    public static final short INT_2 = 0x0011;
    public static final short INT_4 = 0x0012;
    public static final short INT_8 = 0x0013;
    public static final short INT_16 = 0x0014;
    public static final short URL = 0x0040;
    public static final short UUID = 0x0018;
    public static final short BOOL = 0x0028;
    public static final short STRING = 0x0020;
    public static final short DATSEQ = 0x0030;
    public static final short DATALT = 0x0038;
    public static final short BYTESEQ = 0x0039;

    private Object value;
    private short valueType;

    private ByteArrayOutputStream out;
    private InputStream in;
    private int pos;

    public boolean load(DataElement e)
    {
        this.value = e.value;
        this.valueType = e.valueType;
        return true;
    }

    public boolean load(byte[] data)
    {
        boolean flag = false;
        DataElement element = null;

        in = new ByteArrayInputStream(data);

        try {
            element = readElement();
            this.value = element.value;
            this.valueType = element.valueType;
            flag = true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return flag;
    }

    public byte[] dump()
    {
        if (out == null) {
            out = new ByteArrayOutputStream();
        } else {
            out.reset();
        }

        try {
            writeElement(this);
        } catch (IOException e) {
            e.printStackTrace();
            return new byte[0];
        }

        return this.out.toByteArray();
    }

    public DataElement(byte[] data)
    {
        load(data);
    }

    public DataElement(short valueType)
    {
        switch (valueType) {
        case NULL:
            value = null;
            break;
        case DATALT:
        case DATSEQ:
            value = new Vector();
            break;
        default:
            throw new IllegalArgumentException(
                "valueType is not DATSEQ, DATALT or NULL");
        }

        this.valueType = valueType;
    }

    public DataElement(boolean bool)
    {
        value = bool ? Boolean.TRUE : Boolean.FALSE;
        valueType = BOOL;
    }

    public DataElement(short valueType, long value)
    {
        switch (valueType) {
        case U_INT_1:
            if (value < 0 || value > 0xff) {
                throw new IllegalArgumentException(value + " not U_INT_1");
            }
            break;
        case U_INT_2:
            if (value < 0 || value > 0xffff) {
                throw new IllegalArgumentException(value + " not U_INT_2");
            }
            break;
        case U_INT_4:
            if (value < 0 || value > 0xffffffffl) {
                throw new IllegalArgumentException(value + " not U_INT_4");
            }
            break;
        case INT_1:
            if (value < -0x80 || value > 0x7f) {
                throw new IllegalArgumentException(value + " not INT_1");
            }
            break;
        case INT_2:
            if (value < -0x8000 || value > 0x7fff) {
                throw new IllegalArgumentException(value + " not INT_2");
            }
            break;
        case INT_4:
            if (value < -0x80000000 || value > 0x7fffffff) {
                throw new IllegalArgumentException(value + " not INT_4");
            }
            break;
        case INT_8:
            // Not boundaries tests
            break;
        default:
            throw new IllegalArgumentException(
                "type can't be represented long");
        }

        this.value = new Long(value);
        this.valueType = valueType;
    }

    public DataElement(short valueType, Object value)
    {
        if (value == null) {
            throw new IllegalArgumentException("value param is null");
        }
        switch (valueType) {
        case URL:
        case STRING:
            if (!(value instanceof String)) {
                throw new IllegalArgumentException(
                    "value param should be String");
            }
            break;
        case BYTESEQ:
            if (!(value instanceof byte[])) {
                throw new IllegalArgumentException(
                    "value param should be byte[]");
            }
            break;
        case UUID:
            if (!(value instanceof UUID)) {
                throw new IllegalArgumentException(
                    "value param should be UUID");
            }
            break;
        case U_INT_8:
            if (!(value instanceof byte[]) || ((byte[])value).length != 8) {
                throw new IllegalArgumentException(
                    "value param should be byte[8]");
            }
            break;
        case U_INT_16:
        case INT_16:
            if (!(value instanceof byte[]) || ((byte[])value).length != 16) {
                throw new IllegalArgumentException(
                    "value param should be byte[16]");
            }
            break;
        default:
            throw new IllegalArgumentException(
                "type can't be represented by Object");
        }
        this.value = value;
        this.valueType = valueType;
    }

    public void addElement(DataElement elem)
    {
        if (elem == null) {
            throw new NullPointerException("elem param is null");
        }
        switch (valueType) {
        case DATALT:
        case DATSEQ:
            ((Vector)value).addElement(elem);
            break;
        default:
            throw new ClassCastException("DataType is not DATSEQ or DATALT");
        }
    }

    public void insertElementAt(DataElement elem, short index)
    {
        if (elem == null) {
            throw new NullPointerException("elem param is null");
        }
        switch (valueType) {
        case DATALT:
        case DATSEQ:
            ((Vector)value).insertElementAt(elem, index);
            break;
        default:
            throw new ClassCastException("DataType is not DATSEQ or DATALT");
        }
    }

    public short getSize()
    {
        switch (valueType) {
        case DATALT:
        case DATSEQ:
            return (short)((Vector)value).size();
        default:
            throw new ClassCastException("DataType is not DATSEQ or DATALT");
        }
    }

    public boolean removeElement(DataElement elem)
    {
        if (elem == null) {
            throw new NullPointerException("elem param is null");
        }
        switch (valueType) {
        case DATALT:
        case DATSEQ:
            return ((Vector)value).removeElement(elem);
        default:
            throw new ClassCastException("DataType is not DATSEQ or DATALT");
        }
    }

    public short getDataType()
    {
        return valueType;
    }

    public long getLong()
    {
        switch (valueType) {
        case U_INT_1:
        case U_INT_2:
        case U_INT_4:
        case INT_1:
        case INT_2:
        case INT_4:
        case INT_8:
            return ((Long)value).longValue();
        default:
            throw new ClassCastException("DataType is not INT");
        }
    }

    public boolean getBoolean()
    {
        if (valueType == BOOL) {
            return ((Boolean)value).booleanValue();
        } else {
            throw new ClassCastException("DataType is not BOOL");
        }
    }

    public Object getValue()
    {
        switch (valueType) {
        case URL:
        case STRING:
        case UUID:
        case BYTESEQ:
            return value;
        case U_INT_8:
        case U_INT_16:
        case INT_16:
            // Modifying the returned Object will not change this DataElemen
            return Helper.clone((byte[])value);
        case DATSEQ:
        case DATALT:
            return ((Vector)value).elements();
        default:
            throw new ClassCastException("DataType is simple java type");
        }
    }

    public void write(int oneByte) throws IOException
    {
        this.out.write(oneByte);
    }

    private void writeLong(long l, int size) throws IOException
    {
        for (int i = 0; i < size; i++) {
            write((int)(l >> (size - 1 << 3)));
            l <<= 8;
        }
    }

    private void writeBytes(byte[] b) throws IOException
    {
        for (int i = 0; i < b.length; i++) {
            write(b[i]);
        }
    }

    private void writeElement(DataElement d) throws IOException
    {
        switch (d.getDataType()) {
        case DataElement.NULL:
            write(0 | 0);
            break;

        case DataElement.U_INT_1:
            write(8 | 0);
            writeLong(d.getLong(), 1);
            break;
        case DataElement.U_INT_2:
            write(8 | 1);
            writeLong(d.getLong(), 2);
            break;
        case DataElement.U_INT_4:
            write(8 | 2);
            writeLong(d.getLong(), 4);
            break;
        case DataElement.U_INT_8:
            write(8 | 3);
            writeBytes((byte[])d.getValue());
            break;
        case DataElement.U_INT_16:
            write(8 | 4);
            writeBytes((byte[])d.getValue());
            break;

        case DataElement.INT_1:
            write(16 | 0);
            writeLong(d.getLong(), 1);
            break;
        case DataElement.INT_2:
            write(16 | 1);
            writeLong(d.getLong(), 2);
            break;
        case DataElement.INT_4:
            write(16 | 2);
            writeLong(d.getLong(), 4);
            break;
        case DataElement.INT_8:
            write(16 | 3);
            writeLong(d.getLong(), 8);
            break;
        case DataElement.INT_16:
            write(16 | 4);
            writeBytes((byte[])d.getValue());
            break;

        case DataElement.UUID:
            long uuid = Helper.UUIDTo32Bit((UUID)d.getValue());
            if (uuid == -1) {
                write(24 | 4);
                writeBytes(Helper.UUIDToByteArray((UUID)d.getValue()));
            } else if (uuid <= 0xFFFF) {
                write(24 | 1);
                writeLong(uuid, 2);
            } else {
                write(24 | 2);
                writeLong(uuid, 4);
            }
            break;

        case DataElement.STRING: {
            byte[] b;
            b = Helper.getASCIIBytes((String)d.getValue());

            if (b.length < 0x100) {
                write(32 | 5);
                writeLong(b.length, 1);
            } else if (b.length < 0x10000) {
                write(32 | 6);
                writeLong(b.length, 2);
            } else {
                write(32 | 7);
                writeLong(b.length, 4);
            }

            writeBytes(b);
            break;
        }

        case DataElement.BYTESEQ: {
            byte[] b = (byte[])d.getValue();

            if (b.length < 0x100) {
                write(72 | 5);
                writeLong(b.length, 1);
            } else if (b.length < 0x10000) {
                write(72 | 6);
                writeLong(b.length, 2);
            } else {
                write(72 | 7);
                writeLong(b.length, 4);
            }

            writeBytes(b);
            break;
        }

        case DataElement.BOOL:
            write(40 | 0);
            writeLong(d.getBoolean() ? 1 : 0, 1);
            break;

        case DataElement.DATSEQ: {
            int sizeDescriptor;
            int len = getLength(d);
            int lenSize;
            if (len < (0xff + 2)) {
                sizeDescriptor = 5;
                lenSize = 1;
            } else if (len < (0xFFFF + 3)) {
                sizeDescriptor = 6;
                lenSize = 2;
            } else {
                sizeDescriptor = 7;
                lenSize = 4;
            }
            len -= (1 + lenSize);
            write(48 | sizeDescriptor);
            writeLong(len, lenSize);

            for (Enumeration e = (Enumeration)d.getValue();
                 e.hasMoreElements();) {
                writeElement((DataElement)e.nextElement());
            }

            break;
        }
        case DataElement.DATALT: {
            int sizeDescriptor;
            int len = getLength(d) - 5;
            int lenSize;
            if (len < 0xff) {
                sizeDescriptor = 5;
                lenSize = 1;
            } else if (len < 0xFFFF) {
                sizeDescriptor = 6;
                lenSize = 2;
            } else {
                sizeDescriptor = 7;
                lenSize = 4;
            }
            write(56 | sizeDescriptor);
            writeLong(len, lenSize);

            for (Enumeration e = (Enumeration)d.getValue();
                 e.hasMoreElements();) {
                writeElement((DataElement)e.nextElement());
            }

            break;
        }
        case DataElement.URL: {
            byte[] b;

            b = Helper.getASCIIBytes((String)d.getValue());

            if (b.length < 0x100) {
                write(64 | 5);
                writeLong(b.length, 1);
            } else if (b.length < 0x10000) {
                write(64 | 6);
                writeLong(b.length, 2);
            } else {
                write(64 | 7);
                writeLong(b.length, 4);
            }

            writeBytes(b);
            break;
        }

        default:
            throw new IOException();
        }
    }

    static int getLength(DataElement d)
    {
        switch (d.getDataType()) {
        case DataElement.NULL:
            return 1;

        case DataElement.BOOL:
        case DataElement.U_INT_1:
        case DataElement.INT_1:
            return 2;

        case DataElement.U_INT_2:
        case DataElement.INT_2:
            return 3;

        case DataElement.U_INT_4:
        case DataElement.INT_4:
            return 5;

        case DataElement.U_INT_8:
        case DataElement.INT_8:
            return 9;

        case DataElement.U_INT_16:
        case DataElement.INT_16:
            return 17;

        case DataElement.UUID:
            long uuid = Helper.UUIDTo32Bit((UUID)d.getValue());
            if (uuid == -1) {
                return 1 + 16;
            } else if (uuid <= 0xFFFF) {
                return 1 + 2;
            } else {
                return 1 + 4;
            }
        case DataElement.STRING: {
            byte[] b;
            b = Helper.getASCIIBytes((String)d.getValue());
            if (b.length < 0x100) {
                return b.length + 2;
            } else if (b.length < 0x10000) {
                return b.length + 3;
            } else {
                return b.length + 5;
            }
        }
        case DataElement.BYTESEQ: {
            byte[] b = (byte[])d.getValue();

            if (b.length < 0x100) {
                return b.length + 2;
            } else if (b.length < 0x10000) {
                return b.length + 3;
            } else {
                return b.length + 5;
            }
        }
        case DataElement.URL: {
            byte[] b;
            b = ((String)d.getValue()).getBytes();

            if (b.length < 0x100) {
                return b.length + 2;
            } else if (b.length < 0x10000) {
                return b.length + 3;
            } else {
                return b.length + 5;
            }
        }

        case DataElement.DATSEQ:
        case DataElement.DATALT: {
            int result = 1;

            for (Enumeration e = (Enumeration)d.getValue();
                 e.hasMoreElements();) {
                result += getLength((DataElement)e.nextElement());
            }
            if (result < 0xff) {
                result += 1;
            } else if (result < 0xFFFF) {
                result += 2;
            } else {
                result += 4;
            }

            return result;
        }

        default:
            throw new IllegalArgumentException();
        }
    }

    public DataElement readElement() throws IOException
    {
        int header = read();
        int type = header >> 3 & 0x1f;
        int sizeDescriptor = header & 0x07;

        pos++;

        switch (type) {
        case 0: // NULL
            return new DataElement(DataElement.NULL);
        case 1: // U_INT
            switch (sizeDescriptor) {
            case 0:
                return new DataElement(DataElement.U_INT_1, readLong(1));
            case 1:
                return new DataElement(DataElement.U_INT_2, readLong(2));
            case 2:
                return new DataElement(DataElement.U_INT_4, readLong(4));
            case 3:
                return new DataElement(DataElement.U_INT_8, readBytes(8));
            case 4:
                return new DataElement(DataElement.U_INT_16, readBytes(16));
            default:
                throw new IOException();
            }
        case 2: // INT
            switch (sizeDescriptor) {
            case 0:
                return new DataElement(DataElement.INT_1,
                                       (long)(byte)readLong(1));
            case 1:
                return new DataElement(DataElement.INT_2,
                                       (long)(short)readLong(2));
            case 2:
                return new DataElement(DataElement.INT_4,
                                       (long)(int)readLong(4));
            case 3:
                return new DataElement(DataElement.INT_8, readLong(8));
            case 4:
                return new DataElement(DataElement.INT_16, readBytes(16));
            default:
                throw new IOException();
            }
        case 3: // UUID
        {
            UUID uuid = null;

            switch (sizeDescriptor) {
            case 1:
                long msb = readLong(2);
                uuid = new UUID(msb, 0);
                break;
            case 2:
                uuid = new UUID(readLong(4), 0);
                break;
            case 4:
                // uuid = new UUID(hexString(readBytes(16)), false);
                uuid = java.util.UUID.nameUUIDFromBytes(readBytes(16));
                break;
            default:
                throw new IOException();
            }

            return new DataElement(DataElement.UUID, uuid);
        }
        case 4: // STRING
        {
            int length = -1;

            switch (sizeDescriptor) {
            case 5:
                length = readInteger(1);
                break;
            case 6:
                length = readInteger(2);
                break;
            case 7:
                length = readInteger(4);
                break;
            default:
                throw new IOException();
            }
            String strValue = Helper.newStringUTF8(readBytes(length));
            // DebugLog.debug("DataElement.STRING", strValue,
            // Integer.toString(length - strValue.length()));
            return new DataElement(DataElement.STRING, strValue);
        }
        case 5: // BOOL
            return new DataElement(readLong(1) != 0);
        case 6: // DATSEQ
        {
            int length;

            switch (sizeDescriptor) {
            case 5:
                length = readInteger(1);
                break;
            case 6:
                length = readInteger(2);
                break;
            case 7:
                length = readInteger(4);
                break;
            default:
                throw new IOException();
            }

            DataElement element = new DataElement(DataElement.DATSEQ);

            int started = pos;

            for (int end = pos + length; pos < end;) {
                element.addElement(readElement());
            }
            if (started + length != pos) {
                throw new IOException("DATSEQ size corruption "
                                      + (started + length - pos));
            }
            return element;
        }
        case 7: // DATALT
        {
            int length;

            switch (sizeDescriptor) {
            case 5:
                length = readInteger(1);
                break;
            case 6:
                length = readInteger(2);
                break;
            case 7:
                length = readInteger(4);
                break;
            default:
                throw new IOException();
            }

            DataElement element = new DataElement(DataElement.DATALT);

            int started = pos;

            for (long end = pos + length; pos < end;) {
                element.addElement(readElement());
            }
            if (started + length != pos) {
                throw new IOException("DATALT size corruption "
                                      + (started + length - pos));
            }
            return element;
        }
        case 8: // URL
        {
            int length;

            switch (sizeDescriptor) {
            case 5:
                length = readInteger(1);
                break;
            case 6:
                length = readInteger(2);
                break;
            case 7:
                length = readInteger(4);
                break;
            default:
                throw new IOException();
            }

            return new DataElement(DataElement.URL,
                                   Helper.newStringASCII(readBytes(length)));
        }
        case 9: // BYTESEQ
        {
            int length = -1;

            switch (sizeDescriptor) {
            case 5:
                length = readInteger(1);
                break;
            case 6:
                length = readInteger(2);
                break;
            case 7:
                length = readInteger(4);
                break;
            default:
                throw new IOException();
            }
            byte[] byteseq = readBytes(length);
            // DebugLog.debug("DataElement.STRING", strValue,
            // Integer.toString(length - strValue.length()));
            return new DataElement(DataElement.BYTESEQ, byteseq);
        }
        default:
            throw new IOException("Unknown type " + type);
        }
    }

    public int read() throws IOException
    {
        int v = in.read();
        return v;
    }

    private long readLong(int size) throws IOException
    {
        long result = 0;
        for (int i = 0; i < size; i++) {
            result = result << 8 | read();
        }
        pos += size;
        return result;
    }

    private int readInteger(int size) throws IOException
    {
        int result = 0;
        for (int i = 0; i < size; i++) {
            result = result << 8 | read();
        }
        pos += size;
        return result;
    }

    private byte[] readBytes(int size) throws IOException
    {
        byte[] result = new byte[size];
        for (int i = 0; i < size; i++) {
            result[i] = (byte)read();
        }
        pos += size;
        return result;
    }

    private String hexString(byte[] b) throws IOException
    {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < b.length; i++) {
            buf.append(Integer.toHexString(b[i] >> 4 & 0xf));
            buf.append(Integer.toHexString(b[i] & 0xf));
        }
        return buf.toString();
    }
}

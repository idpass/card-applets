/**
 *  BlueCove - Java library for Bluetooth
 *
 *  Java docs licensed under the Apache License, Version 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *   (c) Copyright 2001, 2002 Motorola, Inc.  ALL RIGHTS RESERVED.
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 *  @version $Id$
 */
package org.idpass.offcard.proto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Vector;

import org.idpass.offcard.misc.Helper;

//clang-format off
// Type Descriptor Table
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
| 0 | 1 | 0 | 0 | 1 |  5              | EC private key              |
|---|---|---|---|---|-----------------|-----------------------------|
| 0 | 1 | 0 | 1 | 0 |  5              | EC public key               |
|-------------------|-----------------|-----------------------------|
| 0 | 1 | 0 | 1 | 1 |  5              | SignatureD (data)           |
|-------------------|-----------------|-----------------------------|
| 0 | 1 | 1 | 0 | 0 |  5              | SignatureH (hash)           |
|-------------------|-----------------|-----------------------------|
| 11-30             |                 | 18 more custom types here   |
|-------------------|-----------------|-----------------------------|
| 1 | 1 | 1 | 1 | 1 |  0              | The type descriptor is      |
|   |   |   |   |   |                 | delegated to the next byte  |
|-------------------------------------|--------------------------- */

// Size Descriptor Table
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
//clang-format on

/**
 * The <code>DataElement</code> class defines the various data types that a
 * Bluetooth service attribute value may have.
 *
 * The following table describes the data types and valid values that a
 * <code>DataElement</code> object can store.
 *
 * <TABLE BORDER>
 * <TR>
 * <TH>Data Type</TH>
 * <TH>Valid Values</TH>
 * </TR>
 * <TR>
 * <TD><code>NULL</code></TD>
 * <TD>represents a <code>null</code> value </TD>
 * </TR>
 * <TR>
 * <TD><code>U_INT_1</code></TD>
 * <TD><code>
 * long </code> value range [0, 255]</TD>
 * </TR>
 * <TR>
 * <TD><code>U_INT_2</code></TD>
 * <TD><code>long</code> value range [0, 2<sup>16</sup>-1]</TD>
 * </TR>
 * <TR>
 * <TD><code>U_INT_4</code></TD>
 * <TD><code>long</code> value range [0, 2<sup>32</sup>-1]</TD>
 * </TR>
 * <TR>
 * <TD><code>U_INT_8</code></TD>
 * <TD><code>byte[]</code> value range [0, 2<sup>64</sup>-1]</TD>
 * </TR>
 * <TR>
 * <TD><code>U_INT_16</code></TD>
 * <TD><code>byte[]</code> value range [0, 2<sup>128</sup>-1]</TD>
 * </TR>
 * <TR>
 * <TD><code>INT_1</code></TD>
 * <TD><code>long</code> value range [-128, 127]</TD>
 * </TR>
 * <TR>
 * <TD><code>INT_2</code></TD>
 * <TD><code>long</code> value range [-2<sup>15</sup>, 2<sup>15</sup>-1]</TD>
 * </TR>
 * <TR>
 * <TD><code>INT_4</code></TD>
 * <TD><code>long</code> value range [-2<sup>31</sup>, 2<sup>31</sup>-1]</TD>
 * </TR>
 * <TR>
 * <TD><code>INT_8</code></TD>
 * <TD><code>long</code> value range [-2<sup>63</sup>, 2<sup>63</sup>-1]</TD>
 * </TR>
 * <TR>
 * <TD><code>INT_16</code></TD>
 * <TD><code>byte[]</code> value range [-2<sup>127</sup>,
 * 2<sup>127</sup>-1]</TD>
 * </TR>
 * <TR>
 * <TD><code>URL</code></TD>
 * <TD><code>java.lang.String</code></TD>
 * </TR>
 * <TR>
 * <TD><code>UUID</code></TD>
 * <TD><code>javax.bluetooth.UUID</code></TD>
 * </TR>
 * <TR>
 * <TD><code>BOOL</code></TD>
 * <TD><code>boolean</code></TD>
 * </TR>
 * <TR>
 * <TD><code>STRING</code></TD>
 * <TD><code>java.lang.String</code></TD>
 * </TR>
 * <TR>
 * <TD><code>DATSEQ</code></TD>
 * <TD><code>java.util.Enumeration</code></TD>
 * </TR>
 * <TR>
 * <TD><code>DATALT</code></TD>
 * <TD><code>java.util.Enumeration</code></TD>
 * </TR>
 * </TABLE>
 *
 *
 */

public class DataElement
{
    /*
     * The following section defines public, static and instance member
     * variables used in the implementation of the methods.
     */

    /**
     * Defines data of type NULL.
     *
     * The value for data type <code>DataElement.NULL</code> is implicit,
     * i.e., there is no representation of it. Accordingly there is no method to
     * retrieve it, and attempts to retrieve the value will throw an exception.
     * <P>
     * The value of <code>NULL</code> is 0x00 (0).
     *
     */
    public static final int NULL = 0x0000;

    /**
     * Defines an unsigned integer of size one byte.
     * <P>
     * The value of the constant <code>U_INT_1</code> is 0x08 (8).
     */
    public static final int U_INT_1 = 0x0008;

    /**
     * Defines an unsigned integer of size two bytes.
     * <P>
     * The value of the constant <code>U_INT_2</code> is 0x09 (9).
     */
    public static final int U_INT_2 = 0x0009;

    /**
     * Defines an unsigned integer of size four bytes.
     * <P>
     * The value of the constant <code>U_INT_4</code> is 0x0A (10).
     */
    public static final int U_INT_4 = 0x000A;

    /**
     * Defines an unsigned integer of size eight bytes.
     * <P>
     * The value of the constant <code>U_INT_8</code> is 0x0B (11).
     */
    public static final int U_INT_8 = 0x000B;

    /**
     * Defines an unsigned integer of size sixteen bytes.
     * <P>
     * The value of the constant <code>U_INT_16</code> is 0x0C (12).
     */
    public static final int U_INT_16 = 0x000C;

    /**
     * Defines a signed integer of size one byte.
     * <P>
     * The value of the constant <code>INT_1</code> is 0x10 (16).
     */
    public static final int INT_1 = 0x0010;

    /**
     * Defines a signed integer of size two bytes.
     * <P>
     * The value of the constant <code>INT_2</code> is 0x11 (17).
     */
    public static final int INT_2 = 0x0011;

    /**
     * Defines a signed integer of size four bytes.
     * <P>
     * The value of the constant <code>INT_4</code> is 0x12 (18).
     */
    public static final int INT_4 = 0x0012;

    /**
     * Defines a signed integer of size eight bytes.
     * <P>
     * The value of the constant <code>INT_8</code> is 0x13 (19).
     */
    public static final int INT_8 = 0x0013;

    /**
     * Defines a signed integer of size sixteen bytes.
     * <P>
     * The value of the constant <code>INT_16</code> is 0x14 (20).
     */
    public static final int INT_16 = 0x0014;

    /**
     * Defines data of type URL.
     * <P>
     * The value of the constant <code>URL</code> is 0x40 (64).
     */
    public static final int URL = 0x0040;

    /**
     * Defines data of type UUID.
     * <P>
     * The value of the constant <code>UUID</code> is 0x18 (24).
     */
    public static final int UUID = 0x0018;

    /**
     * Defines data of type BOOL.
     * <P>
     * The value of the constant <code>BOOL</code> is 0x28 (40).
     */
    public static final int BOOL = 0x0028;

    /**
     * Defines data of type STRING.
     * <P>
     * The value of the constant <code>STRING</code> is 0x20 (32).
     */
    public static final int STRING = 0x0020;

    /**
     * Defines data of type DATSEQ. The service attribute value whose data has
     * this type must consider all the elements of the list, i.e. the value is
     * the whole set and not a subset. The elements of the set can be of any
     * type defined in this class, including DATSEQ.
     * <P>
     * The value of the constant <code>DATSEQ</code> is 0x30 (48).
     */
    public static final int DATSEQ = 0x0030;

    /**
     * Defines data of type DATALT. The service attribute value whose data has
     * this type must consider only one of the elements of the set, i.e., the
     * value is the not the whole set but only one element of the set. The user
     * is free to choose any one element. The elements of the set can be of any
     * type defined in this class, including DATALT.
     * <P>
     * The value of the constant <code>DATALT</code> is 0x38 (56).
     */
    public static final int DATALT = 0x0038;

    public static final int PRIVATEKEY = 0x0039;
    public static final int PUBLICKEY = 0x003A;
    public static final int SIGNATURE_D = 0x003B;
    public static final int SIGNATURE_H = 0x003C;

    static byte[] validHeaders = {
        (byte)0x00, (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C,
        (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x19,
        (byte)0x1A, (byte)0x1C, (byte)0x25, (byte)0x26, (byte)0x28, (byte)0x35,
        (byte)0x36, (byte)0x3D, (byte)0x3E, (byte)0x45, (byte)0x46, (byte)0x4D,
        (byte)0x55, (byte)0x5D, (byte)0x65};

    public static final byte TYPEDESC_NULL = 0x00;
    public static final byte TYPEDESC_INT_1 = 0x02; // differs in sizeDesc
    public static final byte TYPEDESC_INT_2 = 0x02; // differs in sizeDesc
    public static final byte TYPEDESC_DATASEQ = 0x06;
    public static final byte TYPEDESC_DATALT = 0x07;
    public static final byte TYPEDESC_PRIVATEKEY = 0x09;
    public static final byte TYPEDESC_PUBLICKEY = 0x0A;
    public static final byte TYPEDESC_SIGNATURE_D = 0x0B;
    public static final byte TYPEDESC_SIGNATURE_H = 0x0C;

    private Object value;

    private int valueType;

    private ByteArrayOutputStream out;
    private InputStream in;
    private int pos;

    /**
     * Creates a <code>DataElement</code> of type <code>NULL</code>,
     * <code>DATALT</code>, or <code>DATSEQ</code>.
     *
     * @see #NULL
     * @see #DATALT
     * @see #DATSEQ
     *
     * @param valueType
     *            the type of DataElement to create: <code>NULL</code>,
     *            <code>DATALT</code>, or <code>DATSEQ</code>
     *
     * @exception IllegalArgumentException
     *                if <code>valueType</code> is not <code>NULL</code>,
     *                <code>DATALT</code>, or <code>DATSEQ</code>
     */

    public DataElement(int valueType)
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
                "valueType " + typeToString(valueType)
                + " is not DATSEQ, DATALT or NULL");
        }

        this.valueType = valueType;
    }

    /**
     * Creates a <code>DataElement</code> whose data type is <code>BOOL</code>
     * and whose value is equal to <code>bool</code>
     *
     * @see #BOOL
     *
     * @param bool
     *            the value of the <code>DataElement</code> of type BOOL.
     */

    public DataElement(boolean bool)
    {
        value = bool ? Boolean.TRUE : Boolean.FALSE;
        valueType = BOOL;
    }

    /**
     * Creates a <code>DataElement</code> that encapsulates an integer value
     * of size <code>U_INT_1</code>, <code>U_INT_2</code>,
     * <code>U_INT_4</code>, <code>INT_1</code>, <code>INT_2</code>,
     * <code>INT_4</code>, and <code>INT_8</code>. The legal values for
     * the <code>valueType</code> and the corresponding attribute values are:
     * <TABLE>
     * <TR>
     * <TH>Value Type</TH>
     * <TH>Value Range</TH>
     * </TR>
     * <TR>
     * <TD><code>U_INT_1</code></TD>
     * <TD>[0, 2<sup>8</sup>-1]</TD>
     * </TR>
     * <TR>
     * <TD><code>U_INT_2</code></TD>
     * <TD>[0, 2<sup>16</sup>-1]</TD>
     * </TR>
     * <TR>
     * <TD><code>U_INT_4</code></TD>
     * <TD>[0, 2<sup>32</sup>-1]</TD>
     * </TR>
     * <TR>
     * <TD><code>INT_1</code></TD>
     * <TD>[-2<sup>7</sup>, 2<sup>7</sup>-1]</TD>
     * </TR>
     * <TR>
     * <TD><code>INT_2</code></TD>
     * <TD>[-2<sup>15</sup>, 2<sup>15</sup>-1]</TD>
     * </TR>
     * <TR>
     * <TD><code>INT_4</code></TD>
     * <TD>[-2<sup>31</sup>, 2<sup>31</sup>-1]</TD>
     * </TR>
     * <TR>
     * <TD><code>INT_8</code></TD>
     * <TD>[-2<sup>63</sup>, 2<sup>63</sup>-1]</TD>
     * </TR>
     * </TABLE> All other pairings are illegal and will cause an
     * <code>IllegalArgumentException</code> to be thrown.
     *
     * @see #U_INT_1
     * @see #U_INT_2
     * @see #U_INT_4
     * @see #INT_1
     * @see #INT_2
     * @see #INT_4
     * @see #INT_8
     *
     * @param valueType
     *            the data type of the object that is being created; must be one
     *            of the following: <code>U_INT_1</code>,
     *            <code>U_INT_2</code>, <code>U_INT_4</code>,
     *            <code>INT_1</code>, <code>INT_2</code>,
     *            <code>INT_4</code>, or <code>INT_8</code>
     *
     * @param value
     *            the value of the object being created; must be in the range
     *            specified for the given <code>valueType</code>
     *
     * @exception IllegalArgumentException
     *                if the <code>valueType</code> is not valid or the
     *                <code>value</code> for the given legal
     *                <code>valueType</code> is outside the valid range
     *
     */

    public DataElement(int valueType, long value)
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
            throw new IllegalArgumentException("type " + typeToString(valueType)
                                               + " can't be represented long");
        }

        this.value = new Long(value);
        this.valueType = valueType;
    }

    /**
     * Creates a <code>DataElement</code> whose data type is given by
     * <code>valueType</code> and whose value is specified by the argument
     * <code>value</code>. The legal values for the <code>valueType</code>
     * and the corresponding attribute values are: <TABLE>
     * <TR>
     * <TH>Value Type</TH>
     * <TH>Java Type / Value Range</TH>
     * </TR>
     * <TR>
     * <TD><code>URL</code></TD>
     * <TD><code>java.lang.String</code> </TD>
     * </TR>
     * <TR>
     * <TD><code>UUID</code></TD>
     * <TD><code>javax.bluetooth.UUID</code></TD>
     * </TR>
     * <TR>
     * <TD><code>STRING</code></TD>
     * <TD><code>java.lang.String</code></TD>
     * </TR>
     * <TR>
     * <TD><code>INT_16</code></TD>
     * <TD>[-2<sup>127</sup>, 2<sup>127</sup>-1] as a byte array whose
     * length must be 16</TD>
     * </TR>
     * <TR>
     * <TD><code>U_INT_8</code></TD>
     * <TD>[0, 2<sup>64</sup>-1] as a byte array whose length must be 8</TD>
     * </TR>
     * <TR>
     * <TD><code>U_INT_16</code></TD>
     * <TD>[0, 2<sup>128</sup>-1] as a byte array whose length must be 16</TD>
     * </TR>
     * </TABLE> All other pairings are illegal and would cause an
     * <code>IllegalArgumentException</code> exception.
     *
     * @see #URL
     * @see #UUID
     * @see #STRING
     * @see #U_INT_8
     * @see #INT_16
     * @see #U_INT_16
     *
     * @param valueType
     *            the data type of the object that is being created; must be one
     *            of the following: <code>URL</code>, <code>UUID</code>,
     *            <code>STRING</code>, <code>INT_16</code>,
     *            <code>U_INT_8</code>, or <code>U_INT_16</code>
     *
     * @param value
     *            the value for the <code>DataElement</code> being created of
     *            type <code>valueType</code>
     *
     * @exception IllegalArgumentException
     *                if the <code>value</code> is not of the
     *                <code>valueType</code> type or is not in the range
     *                specified or is <code>null</code>
     *
     */

    public DataElement(int valueType, Object value)
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
        case UUID:
            if (!(value instanceof java.util.UUID)) {
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
        case PRIVATEKEY:
            // if (!(value instanceof byte[])) {
            if (!(value instanceof BigInteger)) {
                throw new IllegalArgumentException(
                    "value param should be BigInteger");
            }
            byte[] tmpbuf = ((BigInteger)(value)).toByteArray();
            value = Arrays.copyOfRange(tmpbuf, 1, tmpbuf.length);
            break;
        case PUBLICKEY:
            // if (!(value instanceof byte[])) {
            if (!(value instanceof BigInteger)) {
                throw new IllegalArgumentException(
                    "value param should be BigInteger");
            }
            byte[] buf = ((BigInteger)(value)).toByteArray();
            byte[] buf2 = new byte[buf.length + 1];
            buf2[0] = 0x04;
            System.arraycopy(buf, 0, buf2, 1, buf2.length - 1);
            value = buf2;
            break;
        case SIGNATURE_D:
            if (!(value instanceof byte[])) {
                throw new IllegalArgumentException(
                    "value param should be byte[8]");
            }
            break;
        case SIGNATURE_H:
            if (!(value instanceof byte[])) {
                throw new IllegalArgumentException(
                    "value param should be byte[8]");
            }
            break;
        default:
            throw new IllegalArgumentException(
                "type " + typeToString(valueType)
                + " can't be represented by Object");
        }
        this.value = value;
        this.valueType = valueType;
    }

    /**
     * Adds a <code>DataElement</code> to this <code>DATALT</code> or
     * <code>DATSEQ</code> <code>DataElement</code> object. The
     * <code>elem</code> will be added at the end of the list. The
     * <code>elem</code> can be of any <code>DataElement</code> type, i.e.,
     * <code>URL</code>, <code>NULL</code>, <code>BOOL</code>,
     * <code>UUID</code>, <code>STRING</code>, <code>DATSEQ</code>,
     * <code>DATALT</code>, and the various signed and unsigned integer
     * types. The same object may be added twice. If the object is successfully
     * added the size of the <code>DataElement</code> is increased by one.
     *
     * @param elem
     *            the <code>DataElement</code> object to add
     *
     * @exception ClassCastException
     *                if the method is invoked on a <code>DataElement</code>
     *                whose type is not <code>DATALT</code> or
     *                <code>DATSEQ</code>
     *
     * @exception NullPointerException
     *                if <code>elem</code> is <code>null</code>
     *
     */

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

    /**
     * Inserts a <code>DataElement</code> at the specified location. This
     * method can be invoked only on a <code>DATALT</code> or
     * <code>DATSEQ</code> <code>DataElement</code>. <code>elem</code>
     * can be of any <code>DataElement</code> type, i.e., <code>URL</code>,
     * <code>NULL</code>, <code>BOOL</code>, <code>UUID</code>,
     * <code>STRING</code>, <code>DATSEQ</code>, <code>DATALT</code>,
     * and the various signed and unsigned integers. The same object may be
     * added twice. If the object is successfully added the size will be
     * increased by one. Each element with an index greater than or equal to the
     * specified index is shifted upward to have an index one greater than the
     * value it had previously.
     * <P>
     * The <code>index</code> must be greater than or equal to 0 and less than
     * or equal to the current size. Therefore, <code>DATALT</code> and
     * <code>DATSEQ</code> are zero-based objects.
     *
     * @param elem
     *            the <code>DataElement</code> object to add
     *
     * @param index
     *            the location at which to add the <code>DataElement</code>
     *
     * @throws ClassCastException
     *             if the method is invoked on an instance of
     *             <code>DataElement</code> whose type is not
     *             <code>DATALT</code> or <code>DATSEQ</code>
     *
     * @throws IndexOutOfBoundsException
     *             if <code>index</code> is negative or greater than the size
     *             of the <code>DATALT</code> or <code>DATSEQ</code>
     *
     * @throws NullPointerException
     *             if <code>elem</code> is <code>null</code>
     *
     */

    public void insertElementAt(DataElement elem, int index)
    {
        if (elem == null) {
            throw new NullPointerException("elem param is null");
        }
        switch (valueType) {
        case DATALT:
        case DATSEQ:
            ((Vector)value).insertElementAt(elem, (short)index);
            break;
        default:
            throw new ClassCastException("DataType is not DATSEQ or DATALT");
        }
    }

    /**
     * Returns the number of <code>DataElements</code> that are present in
     * this <code>DATALT</code> or <code>DATSEQ</code> object. It is
     * possible that the number of elements is equal to zero.
     *
     * @return the number of elements in this <code>DATALT</code> or
     *         <code>DATSEQ</code>
     *
     * @throws ClassCastException
     *             if this object is not of type <code>DATALT</code> or
     *             <code>DATSEQ</code>
     */

    public int getSize()
    {
        switch (valueType) {
        case DATALT:
        case DATSEQ:
            return ((Vector)value).size();
        default:
            throw new ClassCastException("DataType is not DATSEQ or DATALT");
        }
    }

    /**
     * Removes the first occurrence of the <code>DataElement</code> from this
     * object. <code>elem</code> may be of any type, i.e., <code>URL</code>,
     * <code>NULL</code>, <code>BOOL</code>, <code>UUID</code>,
     * <code>STRING</code>, <code>DATSEQ</code>, <code>DATALT</code>,
     * or the variously sized signed and unsigned integers. Only the first
     * object in the list that is equal to <code>elem</code> will be removed.
     * Other objects, if present, are not removed. Since this class doesn't
     * override the <code>equals()</code> method of the <code>Object</code>
     * class, the remove method compares only the references of objects. If
     * <code>elem</code> is successfully removed the size of this
     * <code>DataElement</code> is decreased by one. Each
     * <code>DataElement</code> in the <code>DATALT</code> or
     * <code>DATSEQ</code> with an index greater than the index of
     * <code>elem</code> is shifted downward to have an index one smaller than
     * the value it had previously.
     *
     * @param elem
     *            the <code>DataElement</code> to be removed
     *
     * @return <code>true</code> if the input value was found and removed;
     *         else <code>false</code>
     *
     * @throws ClassCastException
     *             if this object is not of type <code>DATALT</code> or
     *             <code>DATSEQ</code>
     *
     * @throws NullPointerException
     *             if <code>elem</code> is <code>null</code>
     */

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

    /**
     * Returns the data type of the object this <code>DataElement</code>
     * represents.
     *
     * @return the data type of this <code>DataElement<code> object; the legal
     * return values are:
     *        <code>URL</code>,
     *        <code>NULL</code>,
     *        <code>BOOL</code>,
     *        <code>UUID</code>,
     *        <code>STRING</code>,
     *        <code>DATSEQ</code>,
     *        <code>DATALT</code>,
     *        <code>U_INT_1</code>,
     *        <code>U_INT_2</code>,
     *        <code>U_INT_4</code>,
     *        <code>U_INT_8</code>,
     *        <code>U_INT_16</code>,
     *        <code>INT_1</code>,
     *        <code>INT_2</code>,
     *        <code>INT_4</code>,
     *        <code>INT_8</code>, or
     *        <code>INT_16</code>
     *
     */

    public int getDataType()
    {
        return valueType;
    }

    /**
     * Returns the value of the <code>DataElement</code> if it can be
     * represented as a <code>long</code>. The data type of the object must
     * be <code>U_INT_1</code>, <code>U_INT_2</code>, <code>U_INT_4</code>,
     * <code>INT_1</code>, <code>INT_2</code>, <code>INT_4</code>, or
     * <code>INT_8</code>.
     *
     *
     * @return the value of the <code>DataElement</code> as a
     *         <code>long</code>
     *
     * @throws ClassCastException
     *             if the data type of the object is not <code>U_INT_1</code>,
     *             <code>U_INT_2</code>, <code>U_INT_4</code>,
     *             <code>INT_1</code>, <code>INT_2</code>,
     *             <code>INT_4</code>, or <code>INT_8</code>
     */

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

    /**
     * Returns the value of the <code>DataElement</code> if it is represented
     * as a <code>boolean</code>.
     *
     *
     * @return the <code>boolean</code> value of this <code>DataElement</code>
     *         object
     *
     * @throws ClassCastException
     *             if the data type of this object is not of type
     *             <code>BOOL</code>
     */

    public boolean getBoolean()
    {
        if (valueType == BOOL) {
            return ((Boolean)value).booleanValue();
        } else {
            throw new ClassCastException("DataType is not BOOL");
        }
    }

    /**
     * Returns the value of this <code>DataElement</code> as an
     * <code>Object</code>. This method returns the appropriate Java object
     * for the following data types: <code>URL</code>, <code>UUID</code>,
     * <code>STRING</code>, <code>DATSEQ</code>, <code>DATALT</code>,
     * <code>U_INT_8</code>, <code>U_INT_16</code>, and
     * <code>INT_16</code>. Modifying the returned <code>Object</code> will
     * not change this <code>DataElement</code>.
     *
     * The following are the legal pairs of data type and Java object type being
     * returned. <TABLE>
     * <TR>
     * <TH><code>DataElement</code> Data Type</code></TH>
     * <TH>Java Data Type</TH>
     * </TR>
     * <TR>
     * <TD><code>URL</code></TD>
     * <TD><code>java.lang.String</code> </TD>
     * </TR>
     * <TR>
     * <TD><code>UUID</code></TD>
     * <TD><code>javax.bluetooth.UUID</code></TD>
     * </TR>
     * <TR>
     * <TD><code>STRING</code></TD>
     * <TD><code>java.lang.String </code></TD>
     * </TR>
     * <TR>
     * <TD><code>DATSEQ</code></TD>
     * <TD><code>java.util.Enumeration</code></TD>
     * </TR>
     * <TR>
     * <TD><code>DATALT</code></TD>
     * <TD><code>java.util.Enumeration</code></TD>
     * </TR>
     * <TR>
     * <TD><code>U_INT_8</code></TD>
     * <TD>byte[] of length 8</TD>
     * </TR>
     * <TR>
     * <TD><code>U_INT_16</code></TD>
     * <TD>byte[] of length 16</TD>
     * </TR>
     * <TR>
     * <TD><code>INT_16</code></TD>
     * <TD>byte[] of length 16</TD>
     * </TR>
     * </TABLE>
     *
     * @return the value of this object
     *
     * @throws ClassCastException
     *             if the object is not a <code>URL</code>, <code>UUID</code>,
     *             <code>STRING</code>, <code>DATSEQ</code>,
     * <code>DATALT</code>, <code>U_INT_8</code>, <code>U_INT_16</code>, or
     * <code>INT_16</code>
     *
     */

    public Object getValue()
    {
        switch (valueType) {
        case URL:
        case STRING:
        case UUID:
            return value;
        case U_INT_8:
        case U_INT_16:
        case INT_16:
        case PRIVATEKEY:
        case PUBLICKEY:
        case SIGNATURE_D:
        case SIGNATURE_H:
            // Modifying the returned Object will not change this DataElemen
            return Helper.clone((byte[])value);
        case DATSEQ:
        case DATALT:
            return ((Vector)value).elements();
        default:
            throw new ClassCastException("DataType is simple java type");
        }
    }

    private static String typeToString(int type)
    {
        switch (type) {
        case DataElement.NULL:
            return "NULL";
        case DataElement.U_INT_1:
            return "U_INT_1";
        case DataElement.U_INT_2:
            return "U_INT_2";
        case DataElement.U_INT_4:
            return "U_INT_4";
        case DataElement.U_INT_8:
            return "U_INT_8";
        case DataElement.U_INT_16:
            return "U_INT_16";
        case DataElement.INT_1:
            return "INT_1";
        case DataElement.INT_2:
            return "INT_2";
        case DataElement.INT_4:
            return "INT_4";
        case DataElement.INT_8:
            return "INT_8";
        case DataElement.INT_16:
            return "INT_16";
        case DataElement.URL:
            return "URL";
        case DataElement.STRING:
            return "STRING";
        case DataElement.UUID:
            return "UUID";
        case DataElement.DATSEQ:
            return "DATSEQ";
        case DataElement.BOOL:
            return "BOOL";
        case DataElement.DATALT:
            return "DATALT";
        case DataElement.PRIVATEKEY:
            return "PRIVATEKEY";
        case DataElement.PUBLICKEY:
            return "PUBLICKEY";
        case DataElement.SIGNATURE_D:
            return "SIGNATURE_D";
        case DataElement.SIGNATURE_H:
            return "SIGNATURE_H";
        default:
            return "Unknown" + type;
        }
    }

    /**
     * Non JSR-82 function.
     *
     * @deprecated Use ((Object)dataElement).toString() if you want your
     *             application to run in MDIP profile
     */
    public String toString()
    {
        switch (valueType) {
        case U_INT_1:
        case U_INT_2:
        case U_INT_4:
        case INT_1:
        case INT_2:
        case INT_4:
        case INT_8:
            return typeToString(valueType) + " 0x"
                + Helper.toHexString(((Long)value).longValue());
        case BOOL:
        case URL:
        case STRING:
        case UUID:
        case PRIVATEKEY:
        case PUBLICKEY:
        case SIGNATURE_D:
        case SIGNATURE_H:
            return typeToString(valueType) + " " + value.toString();
        case U_INT_8:
        case U_INT_16:
        case INT_16: {
            byte[] b = (byte[])value;

            StringBuffer buf = new StringBuffer();
            buf.append(typeToString(valueType)).append(" ");

            for (int i = 0; i < b.length; i++) {
                buf.append(Integer.toHexString(b[i] >> 4 & 0xf));
                buf.append(Integer.toHexString(b[i] & 0xf));
            }

            return buf.toString();
        }
        case DATSEQ: {
            StringBuffer buf = new StringBuffer("DATSEQ {\n");

            for (Enumeration e = ((Vector)value).elements();
                 e.hasMoreElements();) {
                buf.append(e.nextElement());
                buf.append("\n");
            }

            buf.append("}");

            return buf.toString();
        }
        case DATALT: {
            StringBuffer buf = new StringBuffer("DATALT {\n");

            for (Enumeration e = ((Vector)value).elements();
                 e.hasMoreElements();) {
                buf.append(e.nextElement());
                buf.append("\n");
            }

            buf.append("}");

            return buf.toString();
        }
        default:
            return "Unknown" + valueType;
        }
    }

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

    public byte[] toByteArray()
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
            java.util.UUID uuid = null;

            switch (sizeDescriptor) {
            case 1:
                long msb = readLong(2);
                uuid = new java.util.UUID(msb, 0);
                break;
            case 2:
                uuid = new java.util.UUID(readLong(4), 0);
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
        case 9: // PRIVATEKEY
        {
            int length = readInteger(1);
            byte[] byteseq = readBytes(length);
            return new DataElement(DataElement.PRIVATEKEY, byteseq);
        }
        case 10: // PUBLICKEY
        {
            int length = readInteger(1);
            byte[] byteseq = readBytes(length);
            return new DataElement(DataElement.PUBLICKEY, byteseq);
        }
        case 11: // SIGNATURE_D
        {
            int length = readInteger(1);
            byte[] byteseq = readBytes(length);
            return new DataElement(DataElement.SIGNATURE_D, byteseq);
        }
        case 12: // SIGNATURE_H
        {
            int length = readInteger(1);
            byte[] byteseq = readBytes(length);
            return new DataElement(DataElement.SIGNATURE_H, byteseq);
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
            long uuid = Helper.UUIDTo32Bit((java.util.UUID)d.getValue());
            if (uuid == -1) {
                write(24 | 4);
                writeBytes(
                    Helper.UUIDToByteArray((java.util.UUID)d.getValue()));
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

        case DataElement.PRIVATEKEY: {
            byte[] b = (byte[])d.getValue();
            write(72 | 5);
            writeLong(b.length, 1);
            writeBytes(b);
            break;
        }

        case DataElement.PUBLICKEY: {
            byte[] b = (byte[])d.getValue();
            write(80 | 5);
            writeLong(b.length, 1);
            writeBytes(b);
            break;
        }

        case DataElement.SIGNATURE_D: {
            byte[] b = (byte[])d.getValue();
            write(88 | 5);
            writeLong(b.length, 1);
            writeBytes(b);
            break;
        }

        case DataElement.SIGNATURE_H: {
            byte[] b = (byte[])d.getValue();
            write(96 | 5);
            writeLong(b.length, 1);
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

    private void writeBytes(byte[] b) throws IOException
    {
        for (int i = 0; i < b.length; i++) {
            write(b[i]);
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
            long uuid = Helper.UUIDTo32Bit((java.util.UUID)d.getValue());
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
        case DataElement.PRIVATEKEY: {
            byte[] b = (byte[])d.getValue();
            return b.length + 2;
        }
        case DataElement.PUBLICKEY: {
            byte[] b = (byte[])d.getValue();
            return b.length + 2;
        }
        case DataElement.SIGNATURE_D: {
            byte[] b = (byte[])d.getValue();
            return b.length + 2;
        }
        case DataElement.SIGNATURE_H: {
            byte[] b = (byte[])d.getValue();
            return b.length + 2;
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

    public static boolean validHeader(byte h)
    {
        for (short i = 0; i < validHeaders.length; i++) {
            if (validHeaders[i] == h) {
                return true;
            }
        }

        return false;
    }

    public static byte[] extract(byte[] deBuf, byte t)
    {
        byte[] result = {};
        int n;

        for (int i = 0; i < deBuf.length;) {
            byte header = deBuf[i];

            if (!DataElement.validHeader(header)) {
                return result;
            }

            byte typeDesc = (byte)(header >> 3);
            byte sizeDesc = (byte)(header & 0x07);

            switch (typeDesc) {
            case TYPEDESC_NULL:
                i++;
                break;
            case TYPEDESC_INT_1: // or TYPEDESC_INT_2
                switch (sizeDesc) {
                case 0: // 1 byte
                    i += 2;
                    break;
                case 1: // 2 bytes
                    i += 3;
                    break;
                }
                break;
            case TYPEDESC_DATASEQ:
            case TYPEDESC_DATALT:
                switch (sizeDesc) {
                case 5:
                    i += 2;
                    break;
                case 6:
                    i += 3;
                    break;
                }
                break;
            case TYPEDESC_PRIVATEKEY:
            case TYPEDESC_PUBLICKEY:
            case TYPEDESC_SIGNATURE_H:
            case TYPEDESC_SIGNATURE_D:
                i++;
                n = deBuf[i];
                i++;
                if (t == typeDesc) {
                    result = new byte[n];
                    for (short idx = 0; idx < result.length; idx++) {
                        result[idx] = deBuf[i];
                        i++;
                    }
                    return result;
                } else {
                    i += n;
                }
                break;
            }
        }

        return result;
    }
}

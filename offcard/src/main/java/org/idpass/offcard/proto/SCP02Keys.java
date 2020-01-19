package org.idpass.offcard.proto;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

class SCP02Keys
{
    public byte[] kEnc;
    public byte[] kMac;
    public byte[] kDek;

    SCP02Keys(String kEnc, String kMac, String kDek)
    {
        this.kEnc = Hex.decode(kEnc);
        this.kMac = Hex.decode(kMac);
        this.kDek = Hex.decode(kDek);
    }
}

package org.idpass.offcard.proto;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public interface ICardConnection
{
    ResponseAPDU Transmit(CommandAPDU apdu);
}


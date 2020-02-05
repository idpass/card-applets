package org.idpass.offcard.applet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.idpass.offcard.misc.Helper.Mode;
import org.idpass.offcard.misc.IdpassConfig;
import org.idpass.offcard.misc.Invariant;
import org.idpass.offcard.misc.Dump;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import javacard.framework.SystemException;
import javacard.framework.Util;

import org.idpass.offcard.proto.OffCard;

@IdpassConfig(
    packageAID  = "F769647061737301",
    appletAID   = "F769647061737301010001",
    instanceAID = "F76964706173730101000101",
    capFile = "auth.cap",
    installParams = {
        (byte)0x00,
        (byte)0x05,
        (byte)0x42,
    },
    privileges = { 
        (byte)0xFF,
        (byte)0xFF,
    }
)
public class AuthApplet extends org.idpass.auth.AuthApplet
{
    private static byte[] id_bytes;
    private static Invariant Assert = new Invariant();
    private static AuthApplet instance;

    public static AuthApplet getInstance()
    {
        return instance;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        byte[] retval = new byte[4];
        AuthApplet obj = new AuthApplet(bArray, bOffset, bLength, retval);

        short aid_offset = Util.makeShort(retval[0], retval[1]);
        byte aid_len = retval[2];
        try {
            obj.register(bArray, aid_offset, aid_len);
        } catch (SystemException e) {
            Assert.assertTrue(OffCard.getInstance().getMode() != Mode.SIM,
                              "AuthApplet::install");
        }
        instance = obj;
    }

    @Override public final boolean select()
    {
        if (secureChannel == null) {
            secureChannel = DummyISDApplet.getInstance().getSecureChannel();
        }
        secureChannel.resetSecurity();
        return true;
    }

    public byte[] SELECT()
    {
        return OffCard.getInstance().select(AuthApplet.class);
    }

    private AuthApplet(byte[] bArray,
                       short bOffset,
                       byte bLength,
                       byte[] retval)
    {
        super(bArray, bOffset, bLength, retval);
    }

    public byte[] aid()
    {
        if (id_bytes == null) {
            IdpassConfig cfg
                = AuthApplet.class.getAnnotation(IdpassConfig.class);
            String strId = cfg.instanceAID();
            id_bytes = Hex.decode(strId);
        }

        return id_bytes;
    }
    ////////////////////////////////////////////////////////////////////////////
    // processAddPersona
    public short processAddPersona()
    {
        short newPersonaIndex = (short)0xFFFF;
        CommandAPDU command = new CommandAPDU(0x00, 0x1A, 0x00, 0x00);
        ResponseAPDU response;

        response = OffCard.getInstance().Transmit(command);
        if (0x9000 == response.getSW()) {
            newPersonaIndex = ByteBuffer.wrap(response.getData())
                                  .order(ByteOrder.BIG_ENDIAN)
                                  .getShort();
        }

        return newPersonaIndex;
    }

    // processDeletePersona
    public void processDeletePersona(byte personaIndex)
    {
        byte p2 = personaIndex;
        CommandAPDU command = new CommandAPDU(0x00, 0x1D, 0x00, p2);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        if (response.getSW() == 0x9000) {
            System.out.println("DP success");
        }
    }

    // processAddListener
    public short processAddListener(byte[] listener)
    {
        short newListenerIndex = (short)0xFFFF;
        byte[] data = listener;
        CommandAPDU command = new CommandAPDU(0x00, 0xAA, 0x00, 0x00, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            newListenerIndex = ByteBuffer.wrap(response.getData())
                                   .order(ByteOrder.BIG_ENDIAN)
                                   .getShort();
            System.out.println(
                String.format("AL retval = 0x%04X", newListenerIndex));
        }
        return newListenerIndex;
    }

    // processDeleteListener
    public boolean processDeleteListener(byte[] listener)
    {
        byte[] status = null;
        byte[] data = listener;
        CommandAPDU command = new CommandAPDU(0x00, 0xDA, 0x00, 0x00, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            status = response.getData();
            Dump.print("DL retval", status);
        }
        return status != null && status[0] == 0x01;
    }

    // processAddVerifierForPersona
    public short processAddVerifierForPersona(byte personaId, byte[] authData)
    {
        short newVerifierIndex = (short)0xFFFF;
        byte[] data = authData;
        byte p2 = personaId;
        CommandAPDU command = new CommandAPDU(0x00, 0x2A, 0x00, p2, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            newVerifierIndex = ByteBuffer.wrap(response.getData())
                                   .order(ByteOrder.BIG_ENDIAN)
                                   .getShort();
            System.out.println(
                String.format("AVP retval = 0x%04X", newVerifierIndex));
        }
        return newVerifierIndex;
    }

    // processDeleteVerifierFromPersona
    public void processDeleteVerifierFromPersona(byte personaIndex,
                                                 byte verifierIndex)
    {
        byte p1 = personaIndex;
        byte p2 = verifierIndex;
        CommandAPDU command = new CommandAPDU(0x00, 0x2D, p1, p2);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);
        if (response.getSW() == 0x9000) {
            System.out.println("DVP ok");
        }
    }

    // processAuthenticatePersona
    /*
    cm> AUP ${candidate}
    #####################################################
    AUTHENTICATE_PERSONA
    candidate data:
    7F2E#(81#(268B8129A7402DAC91335793342B8437814237C24238D34238E0423EEE423F4F43433F44521A45662D956D664470745379F2527DE64286EF42905B8697939297A0919AF3929F8D94A2878FA3948FA4A250AB854CB0C651B8CF41B8DA51CAA050D03C4CD54D5DD7175BDBBB50E0255CE5415DE72C4CE7FE41F1B05EF2914EF9C880FC258B))
    #####################################################
     => 04 EF 1D CD 98 38 8A 48 44 DC FA 4B F3 9F E6 36    .....8.HD..K...6
        40 D4 6B AD D7 4F 1A 8B 5D 7B 2E 3E AD 7D 92 15    @.k..O..]{.>.}..
        34 4B C4 FA 63 08 38 77 7A 1F D4 9D 25 6D 7B 00    4K..c.8wz...%m{.
        35 7A 92 C7 3D 31 43 2A 10 2A 32 60 2A A2 A3 17    5z..=1C*.*2`*...
        C2 08 22 7A D3 CF 9C E2 A9 DD 0E 29 CD 86 45 4E    .."z.......)..EN
        79 5C E2 82 03 7F FC 7D 43 43 9F C2 02 69 1F C0    y\.....}CC...i..
        C7 0D 5A 75 76 27 75 62 72 41 65 36 34 DE 58 04    ..Zuv'ubrAe64.X.
        E0 15 52 E3 48 03 84 FA 89 8F D7 F9 26 A0 2B CF    ..R.H.......&.+.
        13 1D 98 AE 7C A7 86 1F 82 8B 21 8B 80 59 E8 C4    ....|.....!..Y..
        81 92 F6 10 82 A6 C1 31 AF B8 9C D0 65             .......1....e
     (186800 usec)
     <= 00 00 40 00 90 00                                  ..@...
    Status: No Error

    cm> /send "00 EF 1D CD #(${candidate})"
     => 00 EF 1D CD 89 7F 2E 86 81 84 26 8B 81 29 A7 40    ..........&..).@
        2D AC 91 33 57 93 34 2B 84 37 81 42 37 C2 42 38    -..3W.4+.7.B7.B8
        D3 42 38 E0 42 3E EE 42 3F 4F 43 43 3F 44 52 1A    .B8.B>.B?OCC?DR.
        45 66 2D 95 6D 66 44 70 74 53 79 F2 52 7D E6 42    Ef-.mfDptSy.R}.B
        86 EF 42 90 5B 86 97 93 92 97 A0 91 9A F3 92 9F    ..B.[...........
        8D 94 A2 87 8F A3 94 8F A4 A2 50 AB 85 4C B0 C6    ..........P..L..
        51 B8 CF 41 B8 DA 51 CA A0 50 D0 3C 4C D5 4D 5D    Q..A..Q..P.<L.M]
        D7 17 5B DB BB 50 E0 25 5C E5 41 5D E7 2C 4C E7    ..[..P.%\.A].,L.
        FE 41 F1 B0 5E F2 91 4E F9 C8 80 FC 25 8B          .A..^..N....%.
     (159495 usec)
     <= 00 00 40 00 90 00                                  ..@...
    Status: No Error

    */
    public int processAuthenticatePersona(byte[] authData)
    {
        int indexScore = 0xFFFFFFFF;
        byte[] data = authData;
        CommandAPDU command = new CommandAPDU(0x00, 0xEF, 0x1D, 0xCD, data);
        ResponseAPDU response;
        response = OffCard.getInstance().Transmit(command);

        if (0x9000 == response.getSW()) {
            indexScore = ByteBuffer.wrap(response.getData())
                             .order(ByteOrder.BIG_ENDIAN)
                             .getInt();
            System.out.println(
                String.format("AUP retval = 0x%08X", indexScore));
        }

        return indexScore;
    }
}

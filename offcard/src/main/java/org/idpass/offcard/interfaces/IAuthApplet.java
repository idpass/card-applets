package org.idpass.offcard.interfaces;

public interface IAuthApplet {
    // processAddPerosana
    public short AP();
    // processDeletePersona
    public void DP(byte personaIndex);
    // processAddListener
    public short AL(byte[] listener);
    // processDeleteListener
    public boolean DL(byte[] listener);
    // processAddVerifierForPersona
    public short AVP(byte personaId, byte[] authData);
    // processDeleteVerifierFromPersona
    public void DVP(byte personaIndex, byte verifierIndex);
    // processAuthenticatePersona
    public int AUP(byte[] authData);

    public byte[] instanceAID();
}

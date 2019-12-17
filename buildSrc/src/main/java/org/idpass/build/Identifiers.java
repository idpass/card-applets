package org.idpass.build;

import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public class Identifiers {
  public static final String PACKAGE_AID_HEX = "0F00BA00000001";
  public static final byte[] PACKAGE_AID =    Hex.decode(PACKAGE_AID_HEX);
  public static final byte[] HELLOWORLD_AID = Hex.decode(PACKAGE_AID_HEX + "01");
  public static final int DEFAULT_INSTANCE_IDX = 1;

  public static final byte[] AUTH_AID = Hex.decode("F76964706173730101000101");
  public static final byte[] SAM_AID  = Hex.decode("F76964706173730201000101");
  public static final byte[] DS_AID   = Hex.decode("F76964706173730301000101");

  /**
   * Gets the instance AID of the default instance of the helloworld applet.
   *
   * @return the instance AID of the helloworld applet
   */
  public static byte[] getInstanceAID() {
    return getInstanceAID(DEFAULT_INSTANCE_IDX);
  }

  /**
   * Gets the instance AID of the helloworld applet with the given index. Since multiple instances of the applet
   * could be installed in parallel, this method allows selecting a specific instance. The index is between 01 and ff
   *
   * @return the instance AID of the helloworld applet
   */
  public static byte[] getInstanceAID(int instanceIdx) {
    if (instanceIdx < 0x01 || instanceIdx > 0xff) {
      throw new IllegalArgumentException("The instance index must be between 1 and 255");
    }

    byte[] instanceAID = Arrays.copyOf(HELLOWORLD_AID, HELLOWORLD_AID.length + 1);
    instanceAID[HELLOWORLD_AID.length] = (byte) instanceIdx;
    return instanceAID;
  }
}

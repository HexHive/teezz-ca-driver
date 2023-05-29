import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

class GatekeeperClient {

  // The binder client proxy we use to interact with gatekeeperd
  Object mIGateKeeperServiceObj;
  Method mEnrollM;
  Method mVerifyM;
  Method mGetResponseCodeM;
  Method mGetPayloadM;

  // static native int registerNatives();
  public GatekeeperClient() {
    init();
  }

  public static void main(String[] args) {
    GatekeeperClient gk = new GatekeeperClient();

    // enroll a password
    byte[] desiredPassword = "bbbbbbbbbbbbbbbb".getBytes();
    byte[] currentPasswordHandle = gk.enroll(0, null, null, desiredPassword);
    gk.verify(0, currentPasswordHandle, desiredPassword);

    // enroll a new password using the previous password handle
    byte[] reenrollPassword = "fedcba0987654321".getBytes();
    currentPasswordHandle = gk.enroll(0, currentPasswordHandle, desiredPassword, reenrollPassword);
    gk.verify(0, currentPasswordHandle, reenrollPassword);
  }

  // http://www.aospxref.com/android-7.1.2_r39/xref/frameworks/base/core/java/android/service/gatekeeper/IGateKeeperService.aidl
  // We need `enroll` and `verify` (optionally `verifyChallenge`,
  // `getSecureUserId`, and `clearSecureUserId`)
  private byte[] enroll(int uid, byte[] currentPasswordHandle, byte[] currentPassword, byte[] desiredPassword) {

    byte[] hash = null;

    try {
      Object gkresp = mEnrollM.invoke(mIGateKeeperServiceObj, 0, currentPasswordHandle, currentPassword,
          desiredPassword);

      Object ret = mGetResponseCodeM.invoke(gkresp);
      byte[] payload = (byte[]) mGetPayloadM.invoke(gkresp);
      hash = payload;

      System.out.println("Enroll returns: " + ret);
    } catch (IllegalAccessException x) {
      x.printStackTrace();
    } catch (InvocationTargetException x) {
      x.printStackTrace();
    }

    return hash;
  }

  private Object verify(int uid, byte[] enrolledPasswordHandle, byte[] providedPassword) {

    Object gkresp = null;
    try {
      gkresp = mVerifyM.invoke(mIGateKeeperServiceObj, 0, enrolledPasswordHandle, providedPassword);

      Object ret = mGetResponseCodeM.invoke(gkresp);
      System.out.println("Verify returns: " + ret);
    } catch (IllegalAccessException x) {
      x.printStackTrace();
    } catch (InvocationTargetException x) {
      x.printStackTrace();
    }

    return gkresp;
  }

  private void init() {

    try {

      Class gateKeeperClass = Class.forName("android.security.GateKeeper");
      Class gateKeeperResponseClass = Class.forName("android.service.gatekeeper.GateKeeperResponse");
      Class iGateKeeperServiceClass = Class.forName("android.service.gatekeeper.IGateKeeperService");
      Method getServiceM = gateKeeperClass.getDeclaredMethod("getService", null);

      mIGateKeeperServiceObj = getServiceM.invoke(null);

      // get methods gk methods
      mEnrollM = iGateKeeperServiceClass.getDeclaredMethod("enroll", int.class, byte[].class, byte[].class,
          byte[].class);
      mVerifyM = iGateKeeperServiceClass.getDeclaredMethod("verify", int.class, byte[].class, byte[].class);

      // get gk response methods
      mGetResponseCodeM = gateKeeperResponseClass.getDeclaredMethod("getResponseCode", null);
      mGetPayloadM = gateKeeperResponseClass.getDeclaredMethod("getPayload", null);

    } catch (ClassNotFoundException x) {
      x.printStackTrace();
    } catch (IllegalAccessException x) {
      x.printStackTrace();
    } catch (NoSuchMethodException x) {
      x.printStackTrace();
    } catch (InvocationTargetException x) {
      x.printStackTrace();
    }
  }
}

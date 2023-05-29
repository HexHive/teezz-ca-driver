import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.math.BigInteger;

public class KeymasterArguments {
  Constructor mConstructor;
  Object oKeystoreArguments;
  Method mAddEnum;
  Method mAddUnsignedInt;
  Method mAddUnsignedLong;
  Method mAddBoolean;
  Method mAddBytes;

  public KeymasterArguments() {
    try {
      Class keystoreArgs = Class.forName("android.security.keymaster.KeymasterArguments");
      mConstructor = keystoreArgs.getConstructor();
      oKeystoreArguments = (Object) mConstructor.newInstance();
      mAddEnum = keystoreArgs.getDeclaredMethod("addEnum", int.class, int.class);
      mAddUnsignedInt = keystoreArgs.getDeclaredMethod("addUnsignedInt", int.class, long.class);
      mAddUnsignedLong = keystoreArgs.getDeclaredMethod("addUnsignedLong", int.class, BigInteger.class);
      mAddBoolean = keystoreArgs.getDeclaredMethod("addBoolean", int.class);
      mAddBytes = keystoreArgs.getDeclaredMethod("addBytes", int.class, byte[].class);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static Class getClassType() {
    try {
      return Class.forName("android.security.keymaster.KeymasterArguments");
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  public Object getInstance() {
    return oKeystoreArguments;
  }

  public void addEnum(int tag, int value) {
    try {
      mAddEnum.invoke(oKeystoreArguments, tag, value);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void addBytes(int tag, byte[] value) {
    try {
      mAddBytes.invoke(oKeystoreArguments, tag, value);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void addUnsignedInt(int tag, long value) {
    try {
      mAddUnsignedInt.invoke(oKeystoreArguments, tag, value);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void addUnsignedLong(int tag, BigInteger value) {
    try {
      mAddUnsignedLong.invoke(oKeystoreArguments, tag, value);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void addBoolean(int tag) {
    try {
      mAddBoolean.invoke(oKeystoreArguments, tag);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

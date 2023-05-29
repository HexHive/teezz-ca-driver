import java.lang.reflect.Constructor;

public class KeystoreArguments {
  Class cKeystoreArguments;
  Object oKeystoreArguments;

  public KeystoreArguments(byte[][] args) {
    try {
      cKeystoreArguments = Class.forName("android.security.KeystoreArguments");
      Constructor constructor = cKeystoreArguments.getDeclaredConstructor(byte[][].class);
      oKeystoreArguments = constructor.newInstance(args);
    } catch (Exception e) {
      e.printStackTrace();
    }

  }

  public Object getInstance() {
    return oKeystoreArguments;
  }

  public static Class getClassType() {
    try {
      return Class.forName("android.security.KeystoreArguments");
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
}

import java.lang.reflect.Constructor;

public class KeymasterBlob {
  Class cKeymasterBlob;
  Constructor constructor;
  Object oKeymasterBlob;

  KeymasterBlob(byte[] blob) {
    try {
      cKeymasterBlob = Class.forName("android.security.keymaster.KeymasterBlob");
      constructor = cKeymasterBlob.getConstructor(byte[].class);
      oKeymasterBlob = constructor.newInstance(blob);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  Object getInstance() {
    return oKeymasterBlob;
  }
}

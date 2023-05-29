import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;

class KeystoreClient {
  public static final int NO_ERROR = 1;
  public static final int LOCKED = 2;
  public static final int UNINITIALIZED = 3;
  public static final int SYSTEM_ERROR = 4;
  public static final int PROTOCOL_ERROR = 5;
  public static final int PERMISSION_DENIED = 6;
  public static final int KEY_NOT_FOUND = 7;
  public static final int VALUE_CORRUPTED = 8;
  public static final int UNDEFINED_ACTION = 9;
  public static final int WRONG_PASSWORD = 10;
  public static final int OP_AUTH_NEEDED = 15;
  public static final int UID_SELF = -1;
  public static final int FLAG_NONE = 0;
  public static final int FLAG_ENCRYPTED = 1;

  public enum State {
    UNLOCKED, LOCKED, UNINITIALIZED
  };

  private Object oKeystoreService;
  private Object token = null;
  private Class cKeyCharacteristics;
  private Class cKeymasterBlob;
  private Class cIBinder;
  private Method mAddRngEntropy;
  private Method mOnUserPasswordChanged;
  private Method mGet;
  private Method mPut;
  private Method mDelete;
  private Method mLock;
  private Method mGenerateKey;
  private Method mGenerate;
  private Method mReset;
  private Method mBegin;
  private Method mUpdate;
  private Method mFinish;
  private Method mImportKey;
  private Method mImport_Key;
  private Method mExportKey;
  private Method mAbort;
  private Method mGetKeyCharacteristics;
  private Method mContains;
  private Method mSign;
  private Method mVerify;

  public boolean addRngEntropy(byte[] bytes) throws Exception {
    return (int) mAddRngEntropy.invoke(oKeystoreService, bytes) == NO_ERROR;
  }

  public boolean lock(int uid) throws Exception {
    int res = (int) mLock.invoke(oKeystoreService, uid);
    return res == NO_ERROR;
  }

  public byte[] get(String key) throws Exception {

    Platform platform = Platform.getInstance();
    if (platform.mAndroidVersion.equals("7.1.2")) {
      return (byte[]) mGet.invoke(oKeystoreService, key, 1000);
    } else {
      return (byte[]) mGet.invoke(oKeystoreService, key);
    }
  }

  public boolean put(String key, byte[] value, int uid, int flags) throws Exception {
    int res = (int) mPut.invoke(oKeystoreService, key, value, uid, flags);
    return res == NO_ERROR;
  }

  public boolean contains(String key) {
    try {
      return (int) mContains.invoke(oKeystoreService, key, 1000) == NO_ERROR;
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }

  public boolean importKey(String keyName, byte[] key, int flags) {
    try {
      return (int) mImport_Key.invoke(oKeystoreService, keyName, key, 1000, flags) == NO_ERROR;
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }

  }

  public int importKey(String alias, Object args, int format, byte[] keyData, int flags,
      Object outCharacteristics) {
    try {
      int res = (int) mImportKey.invoke(oKeystoreService, alias, args, format, keyData, 1000, flags,
          outCharacteristics);
      return res;
    } catch (Exception e) {
      e.printStackTrace();
      return -1;
    }
  }

  public Object exportKey(String alias, int format, Object clientId,
      Object appId) {

    Platform platform = Platform.getInstance();
    try {

      if (platform.mAndroidVersion.equals("7.1.2")) {
        return mExportKey.invoke(oKeystoreService, alias, format, clientId, appId, 1000);
      } else {
        return mExportKey.invoke(oKeystoreService, alias, format, clientId, appId);
      }
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  public boolean delete(String key) {
    try {
      int res = (int) mDelete.invoke(oKeystoreService, key, 1000);
      return res == NO_ERROR || res == KEY_NOT_FOUND;
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }

  public int abort(Object token) {
    try {
      return (int) mAbort.invoke(oKeystoreService, token);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return -1;
  }

  public boolean onUserPasswordChanged(String newPassword) throws Exception {
    return (int) mOnUserPasswordChanged.invoke(oKeystoreService, 0, newPassword) == NO_ERROR;
  }

  public int generateKey(String key, Object args, byte[] entropy, int flags, Object outCharacteristics) {
    try {
      return (int) mGenerateKey.invoke(oKeystoreService, key, args, entropy, 1000, flags, outCharacteristics);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return -1;
  }

  public boolean generate(String key, int keyType, int keySize, int flags, byte[][] args) {
    try {
      return (int) mGenerate.invoke(oKeystoreService, key, 1000, keyType, keySize, flags, args) == NO_ERROR;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  public boolean reset() {
    try {
      return (int) mReset.invoke(oKeystoreService) == NO_ERROR;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  public Object begin(String alias, int purpose, boolean pruneable, Object args, byte[] entropy) {
    Platform platform = Platform.getInstance();
    try {
      if (platform.mAndroidVersion.equals("7.1.2")) {
        return mBegin.invoke(oKeystoreService, getToken(), alias, purpose, pruneable, args, entropy, 1000);
      } else {
        return mBegin.invoke(oKeystoreService, getToken(), alias, purpose, pruneable, args, entropy);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public Object update(Object tkn, Object args, byte[] entropy) {
    try {
      return mUpdate.invoke(oKeystoreService, tkn, args, entropy);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public Object finish(Object tkn, Object args, byte[] signature, byte[] entropy) {
    try {
      return mFinish.invoke(oKeystoreService, tkn, args, signature, entropy);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public byte[] sign(String key, byte[] data) {
    try {
      return (byte[]) mSign.invoke(oKeystoreService, key, data);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public boolean verify(String key, byte[] data, byte[] signature) {
    try {
      return (int) mVerify.invoke(oKeystoreService, key, data, signature) == NO_ERROR;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  public Object getToken() {
    if (token != null)
      return token;
    try {
      Class mBinder = Class.forName("android.os.Binder");
      Constructor mConstructor = mBinder.getDeclaredConstructor();
      token = mConstructor.newInstance();
      return token;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public int getKeyCharacteristics(String alias, Object keymasterblob, Object appId, Object keyCharacteristics) {
    try {

      Platform platform = Platform.getInstance();
      if (platform.mAndroidVersion.equals("7.1.2")) {
        return (int) mGetKeyCharacteristics.invoke(oKeystoreService, alias, keymasterblob, appId,
            1000, keyCharacteristics);
      } else {
        return (int) mGetKeyCharacteristics.invoke(oKeystoreService, alias, keymasterblob, appId,
            keyCharacteristics);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return -1;
  }

  public static void checkNullExit(String s, Object o) {
    if (o == null) {
      System.out.println(s + " is null.");
      System.exit(-1);
    }
  }

  public void getInstanceAttempt() {
    try {
      Class cKeyStore = Class.forName("android.security.KeyStore");
      Method mGetInstance = cKeyStore.getDeclaredMethod("getInstance", null);
      System.out.println(mGetInstance);
      Object oKeystoreService = mGetInstance.invoke(null);
    } catch (Exception e) {
    }
  }

  public KeystoreClient() {
    Platform platform = Platform.getInstance();
    try {
      /*
       * We want to call
       * IKeystoreService service = IKeystoreService.Stub.asInterface(
       * ServiceManager.getService("android.security.IKeystoreService")
       * );
       */

      // Obtain service manager class
      Class cServiceManager = Class.forName("android.os.ServiceManager");
      KeystoreClient.checkNullExit("ServiceManager", cServiceManager);

      // Obtain `IBinder` class
      Class cIBinder = Class.forName("android.os.IBinder");
      KeystoreClient.checkNullExit("IBinder", cIBinder);

      // Obtain `getService` method
      Method mGetService = cServiceManager.getDeclaredMethod("getService", String.class);
      KeystoreClient.checkNullExit("getService", mGetService);

      // Invoke `getService`
      Object oIBinder = mGetService.invoke(null, "android.security.keystore");
      KeystoreClient.checkNullExit("IBinder", oIBinder);

      // Obtain `IKeystoreService` class
      Class iKeystoreService = Class.forName("android.security.IKeystoreService");
      KeystoreClient.checkNullExit("android.security.IKeystoreService",
          iKeystoreService);

      // Obtain `IKeystoreService.Stub` class
      Class cStub = iKeystoreService.getDeclaredClasses()[0];

      KeystoreClient.checkNullExit("IKeystoreService.Stub", cStub);

      // Obtain `asInterface` method
      Method mAsInterface = cStub.getDeclaredMethod("asInterface", cIBinder);
      KeystoreClient.checkNullExit("mAsInteface", mAsInterface);

      Object oKeystore = getKeystoreBinder();
      KeystoreClient.checkNullExit("KeystoreBinder", oKeystore);

      oKeystoreService = mAsInterface.invoke(null, oIBinder); // Final object able to call binder
      KeystoreClient.checkNullExit("KeystoreService", oKeystoreService);

      cKeyCharacteristics = Class.forName("android.security.keymaster.KeyCharacteristics");
      cKeymasterBlob = Class.forName("android.security.keymaster.KeymasterBlob");

      mReset = oKeystoreService.getClass().getDeclaredMethod("reset");
      mAddRngEntropy = oKeystoreService.getClass().getDeclaredMethod("addRngEntropy", byte[].class);

      /*
       * Note that the AOSP contains two versions of the `get()` method.
       * One takes a `uid` while the other does not.
       * bullhead running Android 7.* does only implement the version *with*
       * the `uid` while the P9 Lite running Android 6.* does only implement the
       * version *without* the `uid`.
       */
      if (platform.mAndroidVersion.equals("7.1.2")) {
        mGet = oKeystoreService.getClass().getDeclaredMethod("get", String.class, int.class);
      } else {
        mGet = oKeystoreService.getClass().getDeclaredMethod("get", String.class);
      }

      mPut = oKeystoreService.getClass().getDeclaredMethod("insert", String.class, byte[].class, int.class,
          int.class);
      mDelete = oKeystoreService.getClass().getDeclaredMethod("del", String.class, int.class);
      mContains = oKeystoreService.getClass().getDeclaredMethod("exist", String.class, int.class);
      mLock = oKeystoreService.getClass().getDeclaredMethod("lock", int.class);
      mOnUserPasswordChanged = oKeystoreService.getClass().getDeclaredMethod("onUserPasswordChanged", int.class,
          String.class);
      mGenerateKey = oKeystoreService.getClass().getDeclaredMethod("generateKey", String.class,
          KeymasterArguments.getClassType(), byte[].class, int.class, int.class,
          cKeyCharacteristics);

      mGenerate = oKeystoreService.getClass().getDeclaredMethod("generate", String.class, int.class, int.class,
          int.class, int.class, KeystoreArguments.getClassType());

      /*
       * Same story as for `get()`.
       */
      if (platform.mAndroidVersion.equals("7.1.2")) {
        mBegin = oKeystoreService.getClass().getDeclaredMethod("begin", cIBinder,
            String.class, int.class, boolean.class, KeymasterArguments.getClassType(),
            byte[].class, int.class);
      } else {
        mBegin = oKeystoreService.getClass().getDeclaredMethod("begin", cIBinder,
            String.class, int.class, boolean.class, KeymasterArguments.getClassType(),
            byte[].class);
      }

      mUpdate = oKeystoreService.getClass().getDeclaredMethod("update", cIBinder,
          KeymasterArguments.getClassType(), byte[].class);
      mFinish = oKeystoreService.getClass().getDeclaredMethod("finish", cIBinder,
          KeymasterArguments.getClassType(), byte[].class, byte[].class);

      /*
       * Same story as for `get()`.
       */
      if (platform.mAndroidVersion.equals("7.1.2")) {
        mGetKeyCharacteristics = oKeystoreService.getClass().getDeclaredMethod("getKeyCharacteristics",
            String.class,
            cKeymasterBlob, cKeymasterBlob, int.class, cKeyCharacteristics);
      } else {
        mGetKeyCharacteristics = oKeystoreService.getClass().getDeclaredMethod("getKeyCharacteristics",
            String.class,
            cKeymasterBlob, cKeymasterBlob, cKeyCharacteristics);
      }

      /*
       * Same story as for `get()`.
       */
      if (platform.mAndroidVersion.equals("7.1.2")) {
        mExportKey = oKeystoreService.getClass().getDeclaredMethod("exportKey",
            String.class, int.class, cKeymasterBlob,
            cKeymasterBlob, int.class);
      } else {
        mExportKey = oKeystoreService.getClass().getDeclaredMethod("exportKey",
            String.class, int.class, cKeymasterBlob,
            cKeymasterBlob);

      }

      // KeystoreClient.printMethods(oKeystoreService.getClass());
      mImportKey = oKeystoreService.getClass().getDeclaredMethod("importKey", String.class,
          KeymasterArguments.getClassType(), int.class, byte[].class, int.class, int.class, cKeyCharacteristics);
      mImport_Key = oKeystoreService.getClass().getDeclaredMethod("import_key", String.class, byte[].class, int.class,
          int.class);
      mAbort = oKeystoreService.getClass().getDeclaredMethod("abort", cIBinder);
      mSign = oKeystoreService.getClass().getDeclaredMethod("sign", String.class, byte[].class);
      mVerify = oKeystoreService.getClass().getDeclaredMethod("verify", String.class, byte[].class, byte[].class);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void printMethods(Class cls) {
    for (Method m : cls.getDeclaredMethods()) {
      System.out.println(m);
    }
  }

  public static int getUID(int uid) {
    try {
      Class UserHandle = Class.forName("android.os.UserHandle");
      Method m = UserHandle.getDeclaredMethod("getUserId", int.class);
      return (int) m.invoke(null, uid);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return -1;
  }

  public static int processID() {
    try {
      Class Process = Class.forName("android.os.Process");
      Method m = Process.getDeclaredMethod("myUid");
      int id = (int) m.invoke(null);
      System.out.println("Id = " + id);
      return (int) m.invoke(null);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return -1;
  }

  public static Object getKeystoreBinder() {
    try {
      Class c = Class.forName("android.os.ServiceManager");
      Method m = c.getDeclaredMethod("getService", java.lang.String.class);
      Object o = m.invoke(null, new String("android.security.keystore"));
      return o;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public static Object KeyCharacteristics() {
    try {
      Class cKeyCharacteristics = Class.forName("android.security.keymaster.KeyCharacteristics");
      Constructor constructor = cKeyCharacteristics.getConstructor();
      return constructor.newInstance();
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(-1);
    }
    return null;
  }

}

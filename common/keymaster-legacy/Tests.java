/*
  Tests inspired from http://www.aospxref.com/android-7.1.2_r39/xref/frameworks/base/keystore/tests/src/android/security/KeyStoreTest.java
*/

public class Tests {
  public static final String ANSI_RESET = "\u001B[0m";
  public static final String ANSI_BLACK = "\u001B[30m";
  public static final String ANSI_RED = "\u001B[31m";
  public static final String ANSI_GREEN = "\u001B[32m";
  public static final String ANSI_YELLOW = "\u001B[33m";
  public static final String ANSI_BLUE = "\u001B[34m";
  public static final String ANSI_PURPLE = "\u001B[35m";
  public static final String ANSI_CYAN = "\u001B[36m";
  public static final String ANSI_WHITE = "\u001B[37m";

  private static final byte[] PRIVKEY_BYTES = hexToBytes(
      "308204BE020100300D06092A864886F70D0101010500048204A8308204A4020100028201" +
          "0100E0473E8AB8F2284FEB9E742FF9748FA118ED98633C92F52AEB7A2EBE0D3BE60329BE" +
          "766AD10EB6A515D0D2CFD9BEA7930F0C306537899F7958CD3E85B01F8818524D312584A9" +
          "4B251E3625B54141EDBFEE198808E1BB97FC7CB49B9EAAAF68E9C98D7D0EDC53BBC0FA00" +
          "34356D6305FBBCC3C7001405386ABBC873CB0F3EF7425F3D33DF7B315AE036D2A0B66AFD" +
          "47503B169BF36E3B5162515B715FDA83DEAF2C58AEB9ABFB3097C3CC9DD9DBE5EF296C17" +
          "6139028E8A671E63056D45F40188D2C4133490845DE52C2534E9C6B2478C07BDAE928823" +
          "B62D066C7770F9F63F3DBA247F530844747BE7AAA85D853B8BD244ACEC3DE3C89AB46453" +
          "AB4D24C3AC6902030100010282010037784776A5F17698F5AC960DFB83A1B67564E648BD" +
          "0597CF8AB8087186F2669C27A9ECBDD480F0197A80D07309E6C6A96F925331E57F8B4AC6" +
          "F4D45EDA45A23269C09FC428C07A4E6EDF738A15DEC97FABD2F2BB47A14F20EA72FCFE4C" +
          "36E01ADA77BD137CD8D4DA10BB162E94A4662971F175F985FA188F056CB97EE2816F43AB" +
          "9D3747612486CDA8C16196C30818A995EC85D38467791267B3BF21F273710A6925862576" +
          "841C5B6712C12D4BD20A2F3299ADB7C135DA5E9515ABDA76E7CAF2A3BE80551D073B78BF" +
          "1162C48AD2B7F4743A0238EE4D252F7D5E7E6533CCAE64CCB39360075A2FD1E034EC3AE5" +
          "CE9C408CCBF0E25E4114021687B3DD4754AE8102818100F541884BC3737B2922D4119EF4" +
          "5E2DEE2CD4CBB75F45505A157AA5009F99C73A2DF0724AC46024306332EA898177634546" +
          "5DC6DF1E0A6F140AFF3B7396E6A8994AC5DAA96873472FE37749D14EB3E075E629DBEB35" +
          "83338A6F3649D0A2654A7A42FD9AB6BFA4AC4D481D390BB229B064BDC311CC1BE1B63189" +
          "DA7C40CDECF2B102818100EA1A742DDB881CEDB7288C87E38D868DD7A409D15A43F445D5" +
          "377A0B5731DDBFCA2DAF28A8E13CD5C0AFCEC3347D74A39E235A3CD9633F274DE2B94F92" +
          "DF43833911D9E9F1CF58F27DE2E08FF45964C720D3EC2139DC7CAFC912953CDECB2F355A" +
          "2E2C35A50FAD754CB3B23166424BA3B6E3112A2B898C38C5C15EDB238693390281805182" +
          "8F1EC6FD996029901BAF1D7E337BA5F0AF27E984EAD895ACE62BD7DF4EE45A224089F2CC" +
          "151AF3CD173FCE0474BCB04F386A2CDCC0E0036BA2419F54579262D47100BE931984A3EF" +
          "A05BECF141574DC079B3A95C4A83E6C43F3214D6DF32D512DE198085E531E616B83FD7DD" +
          "9D1F4E2607C3333D07C55D107D1D3893587102818100DB4FB50F50DE8EDB53FF34C80931" +
          "88A0512867DA2CCA04897759E587C244010DAF8664D59E8083D16C164789301F67A9F078" +
          "060D834A2ADBD367575B68A8A842C2B02A89B3F31FCCEC8A22FE395795C5C6C7422B4E5D" +
          "74A1E9A8F30E7759B9FC2D639C1F15673E84E93A5EF1506F4315383C38D45CBD1B14048F" +
          "4721DC82326102818100D8114593AF415FB612DBF1923710D54D07486205A76A3B431949" +
          "68C0DFF1F11EF0F61A4A337D5FD3741BBC9640E447B8B6B6C47C3AC1204357D3B0C55BA9" +
          "286BDA73F629296F5FA9146D8976357D3C751E75148696A40B74685C82CE30902D639D72" +
          "4FF24D5E2E9407EE34EDED2E3B4DF65AA9BCFEB6DF28D07BA6903F165768");

  private static final String TEST_KEYNAME = "test-key";
  private static final String TEST_PASSWD = "12345678";
  private static final int RSA_KEY_SIZE = 1024;
  private static final byte[] TEST_DATA = new byte[RSA_KEY_SIZE / 8];

  private static byte[] hexToBytes(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(
          s.charAt(i + 1), 16));
    }
    return data;
  }

  public static void testGet() {
    printTest("TEST_GET");
    KeystoreClient kc = new KeystoreClient();
    kc.delete("test-key");
    final byte[] TEST_KEYVALUE = "test value".getBytes();
    try {
      assertEquals("Key should not be present", kc.get("test-key") == null, true);
      assertEquals("password change", true, kc.onUserPasswordChanged("1234"));
      kc.lock(1000);
      assertEquals("putting key", kc.put("test-key", TEST_KEYVALUE, 1000, KeystoreClient.FLAG_ENCRYPTED), true);
      assertEquals("key should be the same", new String(kc.get("test-key"), java.nio.charset.StandardCharsets.UTF_8),
          "test value");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void testGetKeyCharacteristicsSuccess() {
    try {
      printTest("TEST_GET_KEY_CHARACTERISTICS");
      KeystoreClient mKeyStore = new KeystoreClient();
      mKeyStore.onUserPasswordChanged("TEST_PASSWD");
      String name = "test";
      Object gen = generateRsaKey(name);
      Object call = KeystoreClient.KeyCharacteristics();
      int result = mKeyStore.getKeyCharacteristics(name, null, null, call);
      assertEquals("getKeyCharacteristics should succeed", KeystoreClient.NO_ERROR, result);
      mKeyStore.delete("test");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void testAppId() {
    printTest("TEST_APP_ID");
    String name = "test";
    byte[] id = new byte[] { 0x01, 0x02, 0x03 };
    KeystoreClient mKeyStore = new KeystoreClient();
    KeymasterArguments args = new KeymasterArguments();
    args.addEnum(KeymasterDefs.KM_TAG_PURPOSE, KeymasterDefs.KM_PURPOSE_ENCRYPT);
    args.addEnum(KeymasterDefs.KM_TAG_PURPOSE, KeymasterDefs.KM_PURPOSE_DECRYPT);
    args.addEnum(KeymasterDefs.KM_TAG_ALGORITHM, KeymasterDefs.KM_ALGORITHM_RSA);
    args.addEnum(KeymasterDefs.KM_TAG_PADDING, KeymasterDefs.KM_PAD_NONE);
    args.addUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, 2048);
    args.addEnum(KeymasterDefs.KM_TAG_BLOCK_MODE, KeymasterDefs.KM_MODE_ECB);
    args.addBoolean(KeymasterDefs.KM_TAG_NO_AUTH_REQUIRED);
    args.addBytes(KeymasterDefs.KM_TAG_APPLICATION_ID, id);
    args.addUnsignedLong(KeymasterDefs.KM_TAG_RSA_PUBLIC_EXPONENT, RSAKeyGenParameterSpec.F4);
    Object outCharacteristics = KeystoreClient.KeyCharacteristics();
    int result = mKeyStore.generateKey(name, args.getInstance(), null, 0, outCharacteristics);
    assertEquals("generateRsaKey should succeed ", KeystoreClient.NO_ERROR, result);
    int result1 = mKeyStore.getKeyCharacteristics(name, null, null,
        outCharacteristics);
    assertEquals("getKeyCharacteristics should fail without application ID",
        KeystoreClient.NO_ERROR, result);
    int result2 = mKeyStore.getKeyCharacteristics(name, new KeymasterBlob(id).getInstance(), null,
        outCharacteristics);
    assertEquals("getKeyCharacteristics should succeed withapplication ID ",
        KeystoreClient.NO_ERROR, result2);
  }

  public static void testExportRsa() {
    printTest("TEST_EXPORT_RSA");
    try {
      String name = "test";
      KeystoreClient mKeyStore = new KeystoreClient();
      generateRsaKey(name);
      Object result = mKeyStore.exportKey(name, KeymasterDefs.KM_KEY_FORMAT_X509, null,
          null);
      if (result == null) {
        assertEquals("result should not be null", false, true);
        return;
      }
      int resultCode = result.getClass().getField("resultCode").getInt(result);
      assertEquals("Export success", KeystoreClient.NO_ERROR, resultCode);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void testImportSuccess() {
    printTest("TEST_IMPORT_SUCCESS");
    try {
      KeystoreClient mKeyStore = new KeystoreClient();
      assertEquals("onUserPasswordChanged passed ", mKeyStore.onUserPasswordChanged(TEST_PASSWD), true);
      assertEquals("Should be able to import key when unlocked", mKeyStore.importKey(TEST_KEYNAME,
          PRIVKEY_BYTES, KeystoreClient.FLAG_ENCRYPTED), true);
      assertEquals("Should contain key", mKeyStore.contains(TEST_KEYNAME), true);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void testAesGcmEncryptSuccess() {
    printTest("TEST_AES_GCM_ENCRYPT");
    String name = "test";
    KeystoreClient mKeyStore = new KeystoreClient();
    assertEquals("Reset", mKeyStore.reset(), true);
    KeymasterArguments args = new KeymasterArguments();
    args.addEnum(KeymasterDefs.KM_TAG_PURPOSE, KeymasterDefs.KM_PURPOSE_ENCRYPT);
    args.addEnum(KeymasterDefs.KM_TAG_PURPOSE, KeymasterDefs.KM_PURPOSE_DECRYPT);
    args.addEnum(KeymasterDefs.KM_TAG_ALGORITHM, KeymasterDefs.KM_ALGORITHM_AES);
    args.addEnum(KeymasterDefs.KM_TAG_PADDING, KeymasterDefs.KM_PAD_NONE);
    args.addUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, 256);
    args.addUnsignedInt(KeymasterDefs.KM_TAG_MIN_MAC_LENGTH, 128);
    args.addEnum(KeymasterDefs.KM_TAG_BLOCK_MODE, KeymasterDefs.KM_MODE_GCM);
    args.addBoolean(KeymasterDefs.KM_TAG_NO_AUTH_REQUIRED);
    Object outCharacteristics = KeystoreClient.KeyCharacteristics();
    int rc = mKeyStore.generateKey(name, args.getInstance(), null, 0, outCharacteristics);
    assertEquals("Generate should succeed", rc, KeystoreClient.NO_ERROR);
    args = new KeymasterArguments();
    args.addEnum(KeymasterDefs.KM_TAG_ALGORITHM, KeymasterDefs.KM_ALGORITHM_AES);
    args.addEnum(KeymasterDefs.KM_TAG_BLOCK_MODE, KeymasterDefs.KM_MODE_GCM);
    args.addEnum(KeymasterDefs.KM_TAG_PADDING, KeymasterDefs.KM_PAD_NONE);
    args.addUnsignedInt(KeymasterDefs.KM_TAG_MAC_LENGTH, 128);
    Object result = mKeyStore.begin(name,
        KeymasterDefs.KM_PURPOSE_ENCRYPT,
        true, args.getInstance(), null);
    // IBinder token = result.token;
    try {
      assertEquals(
          "Begin should succeed ", result.getClass().getDeclaredField("resultCode").getInt(result),
          KeystoreClient.NO_ERROR);
      Object tmpToken = result.getClass().getDeclaredField("token").get(result);
      result = mKeyStore.update(tmpToken, null, new byte[] { 0x01, 0x02, 0x03, 0x04 });
      assertEquals(
          "Update should succeed ", result.getClass().getDeclaredField("resultCode").getInt(result),
          KeystoreClient.NO_ERROR);
      result = mKeyStore.finish(tmpToken, null, null, null);
      assertEquals(
          "Finish should succeed ", result.getClass().getDeclaredField("resultCode").getInt(result),
          KeystoreClient.NO_ERROR);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void testGenerateRsaWithEntropy() {
    printTest("TEST_GENERATE_RSA_WITH_ENTROPY");
    try {
      byte[] entropy = new byte[] { 1, 2, 3, 4, 5 };
      String name = "test";
      KeystoreClient mKeyStore = new KeystoreClient();
      KeymasterArguments args = new KeymasterArguments();
      args.addEnum(KeymasterDefs.KM_TAG_PURPOSE, KeymasterDefs.KM_PURPOSE_ENCRYPT);
      args.addEnum(KeymasterDefs.KM_TAG_PURPOSE, KeymasterDefs.KM_PURPOSE_DECRYPT);
      args.addEnum(KeymasterDefs.KM_TAG_ALGORITHM, KeymasterDefs.KM_ALGORITHM_RSA);
      args.addEnum(KeymasterDefs.KM_TAG_PADDING, KeymasterDefs.KM_PAD_NONE);
      args.addBoolean(KeymasterDefs.KM_TAG_NO_AUTH_REQUIRED);
      args.addUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, 2048);
      args.addUnsignedLong(KeymasterDefs.KM_TAG_RSA_PUBLIC_EXPONENT, RSAKeyGenParameterSpec.F4);
      Object outCharacteristics = KeystoreClient.KeyCharacteristics();
      int result = mKeyStore.generateKey(name, args.getInstance(), entropy, 0, outCharacteristics);
      assertEquals("generateKey should succeed", KeystoreClient.NO_ERROR, result);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static boolean assertEquals(String tp, Object o1, Object o2) {
    if (o1.equals(o2)) {
      System.out.println(ANSI_GREEN + "Assert success " + ANSI_RESET + tp);
      return true;
    } else {
      System.out.println(ANSI_RED + "Assert false " + ANSI_RESET + tp);
      return false;
    }
  }

  private static void printTest(String testName) {
    System.out.println(ANSI_YELLOW + "TESTING " + ANSI_BLUE + testName + ANSI_RESET);
  }

  public static void testSign_Success() {
    try {
      printTest("TEST_SIGN_SUCCESSS");
      KeystoreClient mKeyStore = new KeystoreClient();
      mKeyStore.onUserPasswordChanged(TEST_PASSWD);
      assertEquals("Generating key", mKeyStore.generate(TEST_KEYNAME, 6,
          RSA_KEY_SIZE, KeystoreClient.FLAG_ENCRYPTED, null), true);
      assertEquals("Keystore contains generated key", mKeyStore.contains(TEST_KEYNAME), true);
      final byte[] signature = mKeyStore.sign(TEST_KEYNAME, TEST_DATA);

      assertEquals("Signature should not be null", signature != null, true);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void testVerify_Success() {
    try {
      printTest("TEST_VERIFY_SUCCESS");
      KeystoreClient mKeyStore = new KeystoreClient();
      mKeyStore.onUserPasswordChanged(TEST_PASSWD);
      assertEquals("Generate key", mKeyStore.generate(TEST_KEYNAME, 6,
          RSA_KEY_SIZE, KeystoreClient.FLAG_ENCRYPTED, null), true);
      assertEquals("Keystore contains key", mKeyStore.contains(TEST_KEYNAME), true);
      final byte[] signature = mKeyStore.sign(TEST_KEYNAME, TEST_DATA);
      assertEquals("Signature should not be null", signature != null, true);
      assertEquals("Signature should verify with same data",
          mKeyStore.verify(TEST_KEYNAME, TEST_DATA, signature), true);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static Object generateRsaKey(String name) throws Exception {
    KeymasterArguments args = new KeymasterArguments();
    args.addEnum(KeymasterDefs.KM_TAG_PURPOSE, KeymasterDefs.KM_PURPOSE_ENCRYPT);
    args.addEnum(KeymasterDefs.KM_TAG_PURPOSE, KeymasterDefs.KM_PURPOSE_DECRYPT);
    args.addEnum(KeymasterDefs.KM_TAG_ALGORITHM, KeymasterDefs.KM_ALGORITHM_RSA);
    args.addEnum(KeymasterDefs.KM_TAG_PADDING, KeymasterDefs.KM_PAD_NONE);
    args.addBoolean(KeymasterDefs.KM_TAG_NO_AUTH_REQUIRED);
    args.addUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, 2048);
    args.addUnsignedLong(KeymasterDefs.KM_TAG_RSA_PUBLIC_EXPONENT, RSAKeyGenParameterSpec.F4);

    Object outCharacteristics = KeystoreClient.KeyCharacteristics();
    KeystoreClient kc = new KeystoreClient();
    int result = kc.generateKey(name, args.getInstance(), null, 0, outCharacteristics);
    assertEquals("generateRsaKey should succeed", KeystoreClient.NO_ERROR, result);

    return outCharacteristics;
  }

  interface Test {
    void run();
  }

  private static Test[] tests = new Test[] {

      new Test() {
        public void run() {
          testExportRsa();
        }
      },
      new Test() {
        public void run() {
          if (Platform.getInstance().mAndroidVersion.equals("7.1.2")) {
            // This test crashes `keystore` on the P9 Lite Android 6 (0x0 deref).
            testAppId();
          }
        }
      },
      new Test() {
        public void run() {
          testAesGcmEncryptSuccess();
        }
      },
      new Test() {
        public void run() {
          testGetKeyCharacteristicsSuccess();
        }
      },
      new Test() {
        public void run() {
          testImportSuccess();
        }
      },
      new Test() {
        public void run() {
          testGenerateRsaWithEntropy();
        }
      },
      new Test() {
        public void run() {
          testGet();
        }
      },
      new Test() {
        public void run() {
          testSign_Success();
        }
      },
      new Test() {
        public void run() {
          testVerify_Success();
        }
      }
  };

  public static void main(String[] args) {
    if (args.length != 1) {
      System.out.println("<prog> <test_id>");
      System.exit(0);
    }
    int id = Integer.parseInt(args[0]);
    Tests.tests[id].run();
  }
}

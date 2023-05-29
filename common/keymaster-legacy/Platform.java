import java.lang.reflect.Method;

public class Platform {
    private static Platform mPlatform = null;

    public String mAndroidVersion;

    private Platform() {
        mAndroidVersion = this.getProp("ro.build.version.release");
    }

    public static Platform getInstance() {
        if (mPlatform == null)
            mPlatform = new Platform();

        return mPlatform;
    }

    public String getProp(String key) {
        String propVal;

        try {
            Class<?> c = Class.forName("android.os.SystemProperties");
            Method get = c.getMethod("get", String.class);
            propVal = (String) get.invoke(c, key);
        } catch (Exception e) {
            e.printStackTrace();
            propVal = "";
        }

        return propVal;
    }

}

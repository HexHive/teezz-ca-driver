import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class RSAKeyGenParameterSpec implements AlgorithmParameterSpec {
  private int keysize;
  private BigInteger publicExponent;
  /**
   * The public-exponent value F0 = 3.
   */
  public static final BigInteger F0 = BigInteger.valueOf(3);

  /**
   * The public exponent-value F4 = 65537.
   */
  public static final BigInteger F4 = BigInteger.valueOf(65537);

  /**
   * Constructs a new <code>RSAParameterSpec</code> object from the
   * given keysize and public-exponent value.
   *
   * @param keysize        the modulus size (specified in number of bits)
   * @param publicExponent the public exponent
   */
  public RSAKeyGenParameterSpec(int keysize, BigInteger publicExponent) {
    this.keysize = keysize;
    this.publicExponent = publicExponent;
  }

  /**
   * Returns the keysize.
   *
   * @return the keysize.
   */
  public int getKeysize() {
    return keysize;
  }

  /**
   * Returns the public-exponent value.
   *
   * @return the public-exponent value.
   */
  public BigInteger getPublicExponent() {
    return publicExponent;
  }
}

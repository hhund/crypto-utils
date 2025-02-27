package de.hsheilbronn.mi.utils.crypto.keypair;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Objects;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority;
import de.hsheilbronn.mi.utils.crypto.kem.EcDhKemAesGcm;

/**
 * <p>
 * {@link KeyPairGenerator} factory to create {@link KeyPair}s for use with {@link CertificateAuthority} and
 * {@link EcDhKemAesGcm}.
 * </p>
 * For {@link CertificateAuthority} use:
 * <ul>
 * <li>{@link #rsa(int)}, {@link #rsa1024()}, {@link #rsa2048()}, {@link #rsa3072()} or {@link #rsa4096()}</li>
 * <li>{@link #secp256r1()}, {@link #secp384r1()} or {@link #secp521r1()}</li>
 * <li>{@link #ed25519()} or {@link #ed448()}</li>
 * </ul>
 * For {@link EcDhKemAesGcm} use:
 * <ul>
 * <li>{@link #secp256r1()}, {@link #secp384r1()} or {@link #secp521r1()}</li>
 * <li>{@link #x25519()} or {@link #x448()}</li>
 * </ul>
 */
public class KeyPairGeneratorFactory
{
	private final String algorithm;
	private final AlgorithmParameterSpec params;

	/**
	 * @param algorithm
	 *            not <code>null</code>
	 * @param params
	 *            not <code>null</code>
	 */
	public KeyPairGeneratorFactory(String algorithm, AlgorithmParameterSpec params)
	{
		this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
		this.params = Objects.requireNonNull(params, "params");
	}

	@Override
	public String toString()
	{
		return "KeyPairGeneratorFactory [algorithm=" + algorithm + ", params=" + paramsToString(params) + "]";
	}

	private String paramsToString(AlgorithmParameterSpec params)
	{
		return switch (params)
		{
			case null -> "null";
			case RSAKeyGenParameterSpec r -> {
				String f = "";
				if (RSAKeyGenParameterSpec.F0.equals(r.getPublicExponent()))
					f = " (F0)";
				else if (RSAKeyGenParameterSpec.F4.equals(r.getPublicExponent()))
					f = " (F4)";
				yield params.getClass().getSimpleName() + " [keysize=" + r.getKeysize() + ", publicExponent="
						+ r.getPublicExponent() + f + "]";
			}
			case ECGenParameterSpec e -> params.getClass().getSimpleName() + " [name=" + e.getName() + "]";
			case NamedParameterSpec n -> params.getClass().getSimpleName() + " [name=" + n.getName() + "]";
			default -> params.getClass().getSimpleName() + " [?]";
		};
	}

	/**
	 * @return initialize {@link KeyPairGenerator}
	 * 
	 * @see KeyPairGenerator#initialize(AlgorithmParameterSpec)
	 */
	public KeyPairGenerator initialize()
	{
		try
		{
			KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
			generator.initialize(params);
			return generator;
		}
		catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e)
		{
			throw new RuntimeException(e);
		}
	}

	/**
	 * Insecure, use only for testing.
	 * 
	 * @return RSA 1024 Bit {@link KeyPairGeneratorFactory} for {@link CertificateAuthority}
	 * @see #rsa4096()
	 */
	public static KeyPairGeneratorFactory rsa1024()
	{
		return rsa(1024);
	}

	/**
	 * Not recommended for production use.
	 * 
	 * @return RSA 2048 Bit {@link KeyPairGeneratorFactory} for {@link CertificateAuthority}
	 * @see #rsa4096()
	 */
	public static KeyPairGeneratorFactory rsa2048()
	{
		return rsa(2048);
	}

	/**
	 * Not recommended for production use.
	 * 
	 * @return RSA 3072 Bit {@link KeyPairGeneratorFactory} for {@link CertificateAuthority}
	 * @see #rsa4096()
	 */
	public static KeyPairGeneratorFactory rsa3072()
	{
		return rsa(3072);
	}

	/**
	 * @return RSA 4096 Bit {@link KeyPairGeneratorFactory} for {@link CertificateAuthority}
	 */
	public static KeyPairGeneratorFactory rsa4096()
	{
		return rsa(4096);
	}

	/**
	 * @param keySize
	 *            <code>>= 1204, % 1024 == 0</code>
	 * @return RSA {@link KeyPairGeneratorFactory} for {@link CertificateAuthority}
	 */
	public static KeyPairGeneratorFactory rsa(int keySize)
	{
		if (keySize < 1024 || keySize % 1024 != 0)
			throw new IllegalArgumentException("keySize < 1024 or not multiple of 1024");

		return new KeyPairGeneratorFactory("RSA", new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
	}

	/**
	 * @return secp256r1 {@link KeyPairGeneratorFactory} for {@link CertificateAuthority} and {@link EcDhKemAesGcm}
	 */
	public static KeyPairGeneratorFactory secp256r1()
	{
		return new KeyPairGeneratorFactory("EC", new ECGenParameterSpec("secp256r1"));
	}

	/**
	 * @return secp384r1 {@link KeyPairGeneratorFactory} for {@link CertificateAuthority} and {@link EcDhKemAesGcm}
	 */
	public static KeyPairGeneratorFactory secp384r1()
	{
		return new KeyPairGeneratorFactory("EC", new ECGenParameterSpec("secp384r1"));
	}

	/**
	 * @return secp521r1 {@link KeyPairGeneratorFactory} for {@link CertificateAuthority} and {@link EcDhKemAesGcm}
	 */
	public static KeyPairGeneratorFactory secp521r1()
	{
		return new KeyPairGeneratorFactory("EC", new ECGenParameterSpec("secp521r1"));
	}

	/**
	 * @return Ed25519 {@link KeyPairGeneratorFactory} for {@link CertificateAuthority}
	 */
	public static KeyPairGeneratorFactory ed25519()
	{
		return new KeyPairGeneratorFactory("Ed25519", new NamedParameterSpec("Ed25519"));
	}

	/**
	 * @return Ed448 {@link KeyPairGeneratorFactory} for {@link CertificateAuthority}
	 */
	public static KeyPairGeneratorFactory ed448()
	{
		return new KeyPairGeneratorFactory("Ed448", new NamedParameterSpec("Ed448"));
	}

	/**
	 * @return X25519 {@link KeyPairGeneratorFactory} for {@link EcDhKemAesGcm}
	 */
	public static KeyPairGeneratorFactory x25519()
	{
		return new KeyPairGeneratorFactory("X25519", new NamedParameterSpec("X25519"));
	}

	/**
	 * @return X448 {@link KeyPairGeneratorFactory} for {@link EcDhKemAesGcm}
	 */
	public static KeyPairGeneratorFactory x448()
	{
		return new KeyPairGeneratorFactory("X448", new NamedParameterSpec("X448"));
	}
}

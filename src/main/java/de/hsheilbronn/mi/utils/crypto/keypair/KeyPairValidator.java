package de.hsheilbronn.mi.utils.crypto.keypair;

import java.security.AlgorithmParameters;
import java.security.AsymmetricKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.XECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Predicate;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEM.Decapsulator;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEM.Encapsulator;

public class KeyPairValidator
{
	private KeyPairValidator()
	{
	}

	/**
	 * Checks if the given <b>privateKey</b> and <b>publicKey</b> match by checking if a generated signature can be
	 * verified for RSA, EC and EdDSA key pairs or a Diffie-Hellman key agreement produces the same secret key for a XDH
	 * key pair. If the <b>privateKey</b> is a {@link RSAPrivateCrtKey} and the <b>publicKey</b> is a
	 * {@link RSAPublicKey} modulus and public-exponent will be compared.
	 * 
	 * @param privateKey
	 *            may be <code>null</code>
	 * @param publicKey
	 *            may be <code>null</code>
	 * @return <code>true</code> if the given keys are not <code>null</code> and match
	 */
	public static boolean matches(PrivateKey privateKey, PublicKey publicKey)
	{
		if (privateKey == null || publicKey == null || !privateKey.getAlgorithm().equals(publicKey.getAlgorithm()))
			return false;

		return switch (publicKey.getAlgorithm())
		{
			case "RSA" -> matchesRsa(privateKey, publicKey, "NONEwithRSA");
			case "EC" -> matchesRsaEcEdDsa(privateKey, publicKey, "NONEwithECDSA");
			case "EdDSA" -> matchesRsaEcEdDsa(privateKey, publicKey, "EdDSA");
			case "XDH" -> matchesXdh(privateKey, publicKey);

			default -> throw new IllegalArgumentException(
					"PublicKey algorithm " + publicKey.getAlgorithm() + " not supported");
		};
	}

	private static boolean matchesRsa(PrivateKey privateKey, PublicKey publicKey, String algorithm)
	{
		if (privateKey instanceof RSAPrivateCrtKey rPriv && publicKey instanceof RSAPublicKey rPub)
			return rPriv.getModulus().equals(rPub.getModulus())
					&& rPriv.getPublicExponent().equals(rPub.getPublicExponent());
		else
			return matchesRsaEcEdDsa(privateKey, publicKey, algorithm);
	}

	private static boolean matchesRsaEcEdDsa(PrivateKey privateKey, PublicKey publicKey, String algorithm)
	{
		try
		{
			Signature s = Signature.getInstance(algorithm);
			s.initSign(privateKey);
			byte[] sn = s.sign();

			s.initVerify(publicKey);
			return s.verify(sn);
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e)
		{
			throw new RuntimeException(e);
		}
	}

	private static boolean matchesXdh(PrivateKey privateKey, PublicKey publicKey)
	{
		try
		{
			KEM kem = KEM.getInstance("DHKEM");
			Encapsulator e = kem.newEncapsulator(publicKey);
			Encapsulated ed = e.encapsulate();
			Decapsulator d = kem.newDecapsulator(privateKey);

			return Arrays.equals(ed.key().getEncoded(), d.decapsulate(ed.encapsulation()).getEncoded());
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | DecapsulateException e)
		{
			throw new RuntimeException(e);
		}
	}

	/**
	 * @param expectedKeyLength
	 *            <code>&gt; 0</code>
	 * @return
	 */
	public static Predicate<AsymmetricKey> isRsaKey(int expectedKeyLength)
	{
		if (expectedKeyLength <= 0)
			throw new IllegalArgumentException("expectedKeyLength <= 0");

		// Some external providers emit valid RSA moduli that are one bit below the nominal key size
		return key -> key instanceof RSAKey rsaKey && rsaKey.getModulus().bitLength() >= expectedKeyLength - 1
				&& rsaKey.getModulus().bitLength() <= expectedKeyLength;
	}

	/**
	 * @param expectedCurve
	 *            not <code>null</code>
	 * @return
	 */
	public static Predicate<AsymmetricKey> isXecKey(NamedParameterSpec expectedCurve)
	{
		Objects.requireNonNull(expectedCurve, "expectedCurve");

		return key -> key instanceof XECKey xecKey && xecKey.getParams() instanceof NamedParameterSpec params
				&& expectedCurve.getName().equals(params.getName());
	}

	/**
	 * @param expectedCurve
	 *            not <code>null</code>
	 * @return
	 */
	public static Predicate<AsymmetricKey> isEdecKey(NamedParameterSpec expectedCurve)
	{
		Objects.requireNonNull(expectedCurve, "expectedCurve");

		return key -> key instanceof EdECKey edecKey && edecKey.getParams() instanceof NamedParameterSpec params
				&& expectedCurve.getName().equals(params.getName());
	}

	public static ECParameterSpec namedCurve(String name)
	{
		try
		{
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec(name));
			return parameters.getParameterSpec(ECParameterSpec.class);
		}
		catch (NoSuchAlgorithmException | InvalidParameterSpecException e)
		{
			throw new RuntimeException(e);
		}
	}

	/**
	 * @param expectedCurve
	 *            not <code>null</code>
	 * @return
	 * @see #namedCurve(String)
	 */
	public static Predicate<AsymmetricKey> isEcKey(ECParameterSpec expectedCurve)
	{
		Objects.requireNonNull(expectedCurve, "expectedCurve");

		return key -> key instanceof ECKey ecKey && matchesCurve(ecKey.getParams(), expectedCurve);
	}

	private static boolean matchesCurve(ECParameterSpec actual, ECParameterSpec expected)
	{
		return actual.getCurve().equals(expected.getCurve()) && actual.getGenerator().equals(expected.getGenerator())
				&& actual.getOrder().equals(expected.getOrder()) && actual.getCofactor() == expected.getCofactor();
	}

	public static boolean isRsa1024(AsymmetricKey key)
	{
		return isRsaKey(1024).test(key);
	}

	public static boolean isRsa2048(AsymmetricKey key)
	{
		return isRsaKey(2048).test(key);
	}

	public static boolean isRsa3072(AsymmetricKey key)
	{
		return isRsaKey(3072).test(key);
	}

	public static boolean isRsa4096(AsymmetricKey key)
	{
		return isRsaKey(4096).test(key);
	}

	public static boolean isSecp256r1(AsymmetricKey key)
	{
		return isEcKey(namedCurve("secp256r1")).test(key);
	}

	public static boolean isSecp384r1(AsymmetricKey key)
	{
		return isEcKey(namedCurve("secp384r1")).test(key);
	}

	public static boolean isSecp521r1(AsymmetricKey key)
	{
		return isEcKey(namedCurve("secp521r1")).test(key);
	}

	public static boolean isEd25519(AsymmetricKey key)
	{
		return isEdecKey(NamedParameterSpec.ED25519).test(key);
	}

	public static boolean isEd448(AsymmetricKey key)
	{
		return isEdecKey(NamedParameterSpec.ED448).test(key);
	}

	public static boolean isX25519(AsymmetricKey key)
	{
		return isXecKey(NamedParameterSpec.X25519).test(key);
	}

	public static boolean isX448(AsymmetricKey key)
	{
		return isXecKey(NamedParameterSpec.X448).test(key);
	}
}

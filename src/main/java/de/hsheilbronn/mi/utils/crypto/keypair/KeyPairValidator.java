package de.hsheilbronn.mi.utils.crypto.keypair;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Random;
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

	private static final Random RANDOM = new Random();

	/**
	 * Checks if the given <b>privateKey</b> and <b>publicKey</b> match by checking if a generated signature can be
	 * verified for RSA, EC and EdDSA key pairs or a Diffie-Hellman key agreement produces the same secret key for a XDH
	 * key pair.
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

		return match(publicKey).test(privateKey);
	}

	private static Predicate<PrivateKey> match(PublicKey publicKey)
	{
		return switch (publicKey.getAlgorithm())
		{
			case "RSA" -> matchesRsaEcEdDsa(publicKey, "NONEwithRSA");
			case "EC" -> matchesRsaEcEdDsa(publicKey, "NONEwithECDSA");
			case "EdDSA" -> matchesRsaEcEdDsa(publicKey, "EdDSA");
			case "XDH" -> matchesXdh(publicKey);

			default -> throw new IllegalArgumentException(
					"PublicKey algorithm " + publicKey.getAlgorithm() + " not supported");
		};
	}

	private static Predicate<PrivateKey> matchesRsaEcEdDsa(PublicKey publicKey, String algorithm)
	{
		return privateKey ->
		{
			try
			{
				byte[] b = random(16);

				Signature signature = Signature.getInstance(algorithm);
				signature.initSign(privateKey);
				signature.update(b);

				byte[] signed = signature.sign();

				signature.initVerify(publicKey);
				signature.update(b);

				return signature.verify(signed);
			}
			catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e)
			{
				throw new RuntimeException(e);
			}
		};
	}

	private static byte[] random(int length)
	{
		byte[] b = new byte[length];
		RANDOM.nextBytes(b);
		return b;
	}

	private static Predicate<PrivateKey> matchesXdh(PublicKey publicKey)
	{
		return privateKey ->
		{
			try
			{
				KEM kem = KEM.getInstance("DHKEM");
				Encapsulator e = kem.newEncapsulator(publicKey);
				Encapsulated en = e.encapsulate();
				Decapsulator d = kem.newDecapsulator(privateKey);

				return Arrays.equals(en.key().getEncoded(), d.decapsulate(en.encapsulation()).getEncoded());
			}
			catch (InvalidKeyException | NoSuchAlgorithmException | DecapsulateException e)
			{
				throw new RuntimeException(e);
			}
		};
	}
}

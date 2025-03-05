package de.hsheilbronn.mi.utils.crypto.keypair;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

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
}

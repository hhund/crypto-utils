package de.hsheilbronn.mi.utils.crypto.kem;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.kems.RSAKEMExtractor;
import org.bouncycastle.crypto.kems.RSAKEMGenerator;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * Supports RSA, uses KDF2 with SHA-512
 */
public class RsaKemAesGcm extends AbstractKemAesGcm
{
	/**
	 * With {@link Variant#AES_256} and {@link AbstractKemAesGcm#SECURE_RANDOM}
	 */
	public RsaKemAesGcm()
	{
		this(Variant.AES_256, SECURE_RANDOM);
	}

	/**
	 * With given {@link Variant} and {@link AbstractKemAesGcm#SECURE_RANDOM}
	 * 
	 * @param variant
	 *            not <code>null</code>
	 */
	public RsaKemAesGcm(Variant variant)
	{
		this(variant, SECURE_RANDOM);
	}

	/**
	 * With given {@link Variant} and {@link SecureRandom}
	 * 
	 * @param variant
	 *            not <code>null</code>
	 * @param secureRandom
	 *            not <code>null</code>, to generate random AES initialization vectors and as source of randomness for
	 *            encapsulation
	 */
	public RsaKemAesGcm(Variant variant, SecureRandom secureRandom)
	{
		super(variant, secureRandom, "RSA");
	}

	private DerivationFunction createKeyDerivationFunction()
	{
		return new KDF2BytesGenerator(new SHA512Digest());
	}

	@Override
	protected Encapsulated getEncapsulated(PublicKey publicKey, Variant variant, SecureRandom secureRandom)
			throws NoSuchAlgorithmException, InvalidKeyException
	{
		RSAKEMGenerator encapsulator = new RSAKEMGenerator(variant.size, createKeyDerivationFunction(), secureRandom);
		SecretWithEncapsulation encapsulated = encapsulator.generateEncapsulated(toParameters(publicKey));

		return new Encapsulated(new SecretKeySpec(encapsulated.getSecret(), ALGORITHM_NAME),
				encapsulated.getEncapsulation(), null);
	}

	private RSAKeyParameters toParameters(PublicKey publicKey)
	{
		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
		return new RSAKeyParameters(false, rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent());
	}

	@Override
	protected SecretKey getSecretKey(PrivateKey privateKey, Variant variant, byte[] encapsulation)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException
	{
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
		RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(true, rsaPrivateKey.getModulus(),
				rsaPrivateKey.getPrivateExponent());
		RSAKEMExtractor decapsulator = new RSAKEMExtractor(rsaKeyParameters, variant.size,
				createKeyDerivationFunction());
		return new SecretKeySpec(decapsulator.extractSecret(encapsulation), ALGORITHM_NAME);
	}
}

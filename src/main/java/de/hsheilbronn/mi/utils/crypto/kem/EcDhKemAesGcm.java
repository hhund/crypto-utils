package de.hsheilbronn.mi.utils.crypto.kem;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;

/**
 * Supports EC key algorithms: X25519, X448, secp256r1, secp384r1 and secp521r1
 */
public class EcDhKemAesGcm extends AbstractKemAesGcm
{
	/**
	 * With {@link Variant#AES_256} and {@link AbstractKemAesGcm#SECURE_RANDOM}
	 */
	public EcDhKemAesGcm()
	{
		this(Variant.AES_256, SECURE_RANDOM);
	}

	/**
	 * With given {@link Variant} and {@link AbstractKemAesGcm#SECURE_RANDOM}
	 * 
	 * @param variant
	 *            not <code>null</code>
	 */
	public EcDhKemAesGcm(Variant variant)
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
	public EcDhKemAesGcm(Variant variant, SecureRandom secureRandom)
	{
		super(variant, secureRandom, "EC", "XDH");
	}

	@Override
	protected Encapsulated getEncapsulated(PublicKey publicKey, Variant variant, SecureRandom secureRandom)
			throws NoSuchAlgorithmException, InvalidKeyException
	{
		return createKem().newEncapsulator(publicKey, secureRandom).encapsulate(0, variant.size, ALGORITHM_NAME);
	}

	@Override
	protected SecretKey getSecretKey(PrivateKey privateKey, Variant variant, byte[] encapsulation)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException
	{
		return createKem().newDecapsulator(privateKey).decapsulate(encapsulation, 0, variant.size, ALGORITHM_NAME);
	}

	private KEM createKem() throws NoSuchAlgorithmException
	{
		return KEM.getInstance("DHKEM");
	}
}

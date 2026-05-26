package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.function.Supplier;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.DecapsulateException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.kems.RSAKEMGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * Custom KEM implementation for KEM IDs {@link KemId#RSAKEM_1024_KDF2_SHA256}, {@link KemId#RSAKEM_2048_KDF2_SHA256},
 * {@link KemId#RSAKEM_3072_KDF2_SHA512} and {@link KemId#RSAKEM_4096_KDF2_SHA512}. Not defined in RFC 9180 and thus not
 * compatible with other RFC 9180 implementations.<br>
 * <br>
 * Uses RSA Key Encapsulation Mechanism (RSA-KEM) from ISO 18033-2 via {@link RSAKEMGenerator} for encapsulation and a
 * raw RSA (<code>r = c^d mod n</code>) operation for decapsulation. The shared secret is derived via
 * {@link KDF2BytesGenerator} and {@link SHA256Digest} for 1024 and 2048 bit RSA keys, or {@link SHA512Digest} for 3072
 * and 4096 bit RSA keys.
 */
public class RsaKemWrapper extends AbstractKemWrapper implements KemWrapper
{
	private static final String SHARED_SECRET_KEY_ALGORITHM = "Generic";

	private final Supplier<DerivationFunction> derivationFunctionFactory;

	public RsaKemWrapper(KemId kemId)
	{
		super(kemId);

		derivationFunctionFactory = switch (kemId)
		{
			case RSAKEM_1024_KDF2_SHA256, RSAKEM_2048_KDF2_SHA256 -> () -> new KDF2BytesGenerator(new SHA256Digest());
			case RSAKEM_3072_KDF2_SHA512, RSAKEM_4096_KDF2_SHA512 -> () -> new KDF2BytesGenerator(new SHA512Digest());

			default -> throw new IllegalArgumentException("KemId " + kemId.name() + " not supported");
		};
	}

	@Override
	protected Encapsulated doGetEncapsulated(PublicKey publicKey, SecureRandom secureRandom, int sharedSecretLength)
			throws NoSuchAlgorithmException, InvalidKeyException
	{
		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

		RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(false, rsaPublicKey.getModulus(),
				rsaPublicKey.getPublicExponent());

		RSAKEMGenerator encapsulator = new RSAKEMGenerator(sharedSecretLength, derivationFunctionFactory.get(),
				secureRandom);
		SecretWithEncapsulation encapsulated = encapsulator.generateEncapsulated(rsaKeyParameters);

		return new Encapsulated(new SecretKeySpec(encapsulated.getSecret(), SHARED_SECRET_KEY_ALGORITHM),
				encapsulated.getEncapsulation(), null);
	}

	@Override
	protected SecretKey doGetSharedSecret(PrivateKey privateKey, byte[] encapsulation, int sharedSecretLength)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException
	{
		try
		{
			// no padding to get equivalent operation for: r = c^d mod n
			Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] r = cipher.doFinal(encapsulation);

			DerivationFunction kdf = derivationFunctionFactory.get();
			kdf.init(new KDFParameters(r, null));

			byte[] secret = new byte[sharedSecretLength];
			kdf.generateBytes(secret, 0, secret.length);

			return new SecretKeySpec(secret, SHARED_SECRET_KEY_ALGORITHM);
		}
		catch (InvalidKeyException | DataLengthException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | BadPaddingException | IllegalArgumentException e)
		{
			throw new DecapsulateException(e.getMessage(), e);
		}
	}
}

package de.hsheilbronn.mi.utils.crypto.kem;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public abstract class AbstractKemAesGcm
{
	/**
	 * To generate random AES initialization vectors and as source of randomness for encapsulation.
	 * 
	 * @see #AES_IV_LENGTH
	 */
	public static final SecureRandom SECURE_RANDOM = new SecureRandom();

	/**
	 * Cipher name.
	 * 
	 * @see Cipher#getInstance(String)
	 */
	public static final String CIPHER_NAME = "AES/GCM/NoPadding";

	/**
	 * Symmetric encryption algorithm name.
	 */
	public static final String ALGORITHM_NAME = "AES";

	/**
	 * AES GCM authentication tag length (in bits).
	 */
	public static final int GCM_AUTH_TAG_LENGTH = 128;

	/**
	 * AES initialization vector length (in bytes).
	 */
	public static final int AES_IV_LENGTH = 12;

	/**
	 * Number of bytes at start of encrypted {@link InputStream} representing the encapsulation length in bytes.
	 */
	public static final int ENCAPSULATION_LENGTH_BYTES = 2;

	/**
	 * AES variant with (128, 192, 256) bit keys.
	 */
	public static enum Variant
	{
		AES_128(16), AES_192(24), AES_256(32);

		public int size;

		private Variant(int size)
		{
			this.size = size;
		}
	}

	private final Variant variant;
	private final SecureRandom secureRandom;
	private final Set<String> supportedAsymetricKeyAlgorithms = new HashSet<>();

	protected AbstractKemAesGcm(Variant variant, SecureRandom secureRandom, String... supportedAsymetricKeyAlgorithms)
	{
		Objects.requireNonNull(variant, "variant");
		Objects.requireNonNull(secureRandom, "secureRandom");

		this.variant = variant;
		this.secureRandom = secureRandom;
		this.supportedAsymetricKeyAlgorithms.addAll(List.of(supportedAsymetricKeyAlgorithms));
	}

	/**
	 * Encrypts the given {@link InputStream} with an AES session key calculated by KEM for the given {@link PublicKey}.
	 * The returned {@link InputStream} has the form [encapsulation length (big-endian,
	 * {@value #ENCAPSULATION_LENGTH_BYTES} bytes), encapsulation, AES initialization vector ({@value #AES_IV_LENGTH}
	 * bytes), AES encrypted data].
	 * 
	 * @param data
	 *            not <code>null</code>
	 * @param publicKey
	 *            not <code>null</code>
	 * @return {@link InputStream} of [encapsulation length (big-endian, {@value #ENCAPSULATION_LENGTH_BYTES} bytes),
	 *         encapsulation, iv ({@value #AES_IV_LENGTH} bytes), encrypted data]
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * 
	 * @see KeyPairGeneratorFactory
	 */
	public final InputStream encrypt(InputStream data, PublicKey publicKey) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		Objects.requireNonNull(data, "data");
		Objects.requireNonNull(publicKey, "publicKey");

		if (!supportedAsymetricKeyAlgorithms.contains(publicKey.getAlgorithm()))
			throw new IllegalArgumentException("publicKey.algorithm " + publicKey.getAlgorithm() + " not supported");

		Encapsulated encapsulated = getEncapsulated(publicKey, variant, secureRandom);
		byte[] iv = generateIv();

		Cipher encryptor = Cipher.getInstance(CIPHER_NAME);
		encryptor.init(Cipher.ENCRYPT_MODE, encapsulated.key(), new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, iv));

		int encapsulationLength = encapsulated.encapsulation().length;
		if (encapsulationLength > Short.MAX_VALUE)
			throw new RuntimeException("Encapsulation byte array longer than " + Short.MAX_VALUE);

		return new SequenceInputStream(Collections.enumeration(List.of(
				new ByteArrayInputStream(
						ByteBuffer.allocate(ENCAPSULATION_LENGTH_BYTES).putShort((short) encapsulationLength).array()),
				new ByteArrayInputStream(encapsulated.encapsulation()), new ByteArrayInputStream(iv),
				new CipherInputStream(data, encryptor))));
	}

	private byte[] generateIv()
	{
		byte[] iv = new byte[AES_IV_LENGTH];
		secureRandom.nextBytes(iv);
		return iv;
	}

	protected abstract Encapsulated getEncapsulated(PublicKey publicKey, Variant variant, SecureRandom secureRandom)
			throws NoSuchAlgorithmException, InvalidKeyException;

	/**
	 * @param encrypted
	 *            not <code>null</code>, {@link InputStream} of [encapsulation length (big-endian,
	 *            {@value #ENCAPSULATION_LENGTH_BYTES} bytes), encapsulation, iv ({@value #AES_IV_LENGTH} bytes),
	 *            encrypted data]
	 * @param privateKey
	 *            not <code>null</code>
	 * @return decrypted data
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws DecapsulateException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public final InputStream decrypt(InputStream encrypted, PrivateKey privateKey)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, DecapsulateException,
			NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		Objects.requireNonNull(encrypted, "encrypted");
		Objects.requireNonNull(privateKey, "privateKey");

		if (!supportedAsymetricKeyAlgorithms.contains(privateKey.getAlgorithm()))
			throw new IllegalArgumentException("privateKey.algorithm " + privateKey.getAlgorithm() + " not supported");

		short encapsulationLength = ByteBuffer.wrap(encrypted.readNBytes(ENCAPSULATION_LENGTH_BYTES)).getShort();
		byte[] encapsulation = encrypted.readNBytes(encapsulationLength);
		byte[] iv = encrypted.readNBytes(AES_IV_LENGTH);

		Cipher decryptor = Cipher.getInstance(CIPHER_NAME);
		decryptor.init(Cipher.DECRYPT_MODE, getSecretKey(privateKey, variant, encapsulation),
				new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, iv));

		return new CipherInputStream(encrypted, decryptor);
	}

	protected abstract SecretKey getSecretKey(PrivateKey privateKey, Variant variant, byte[] encapsulation)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException;

	@Override
	public String toString()
	{
		return getClass().getSimpleName() + " [variant=" + variant + "]";
	}
}

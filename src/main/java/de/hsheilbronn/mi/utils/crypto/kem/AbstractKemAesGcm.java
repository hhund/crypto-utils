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
	 * To generate random AES initialization vectors.
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
	public static int GCM_AUTH_TAG_LENGTH = 128;

	/**
	 * AES initialization vector length (in bytes).
	 */
	public static int AES_IV_LENGTH = 12;

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

	protected final Variant variant;
	protected final SecureRandom secureRandom;
	private final Set<String> supportedAsymetricKeyAlgorithms = new HashSet<>();

	public AbstractKemAesGcm(Variant variant, SecureRandom secureRandom, String... supportedAsymetricKeyAlgorithms)
	{
		Objects.requireNonNull(variant, "variant");
		Objects.requireNonNull(secureRandom, "secureRandom");

		this.variant = variant;
		this.secureRandom = secureRandom;
		this.supportedAsymetricKeyAlgorithms.addAll(List.of(supportedAsymetricKeyAlgorithms));
	}

	/**
	 * Encrypts the given {@link InputStream} with an AES session key calculated by DH KEM for the given
	 * {@link PublicKey}. The returned {@link InputStream} has the form [encapsulation length (4 bytes), encapsulation,
	 * AES initialization vector (12 bytes), AES encrypted data].
	 * <p>
	 * 
	 * @param data
	 *            not <code>null</code>
	 * @param publicKey
	 *            not <code>null</code>
	 * @return {@link InputStream} of [encapsulation length (4 bytes), encapsulation, iv (12 bytes), encrypted data]
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

		Encapsulated encapsulated = getEncapsulated(publicKey);

		byte[] iv = new byte[AES_IV_LENGTH];
		secureRandom.nextBytes(iv);

		Cipher encryptor = Cipher.getInstance(CIPHER_NAME);
		encryptor.init(Cipher.ENCRYPT_MODE, encapsulated.key(), new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, iv));

		return new SequenceInputStream(Collections.enumeration(List.of(
				new ByteArrayInputStream(ByteBuffer.allocate(4).putInt(encapsulated.encapsulation().length).array()),
				new ByteArrayInputStream(encapsulated.encapsulation()), new ByteArrayInputStream(iv),
				new CipherInputStream(data, encryptor))));
	}

	protected abstract Encapsulated getEncapsulated(PublicKey publicKey)
			throws NoSuchAlgorithmException, InvalidKeyException;

	/**
	 * @param encrypted
	 *            not <code>null</code>, {@link InputStream} of [encapsulation length (4 bytes), encapsulation, iv (12
	 *            bytes), encrypted data]
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

		byte[] encapsulationLengthBytes = new byte[4];
		int elr = encrypted.read(encapsulationLengthBytes);
		checkReadBytes(4, elr, "encapsulation length");

		int encapsulationLength = ByteBuffer.wrap(encapsulationLengthBytes).getInt();

		byte[] encapsulation = new byte[encapsulationLength];
		int er = encrypted.read(encapsulation);
		checkReadBytes(encapsulationLength, er, "encapsulation");

		byte[] iv = new byte[AES_IV_LENGTH];
		int ivr = encrypted.read(iv);
		checkReadBytes(AES_IV_LENGTH, ivr, "initialization vector");

		Cipher decryptor = Cipher.getInstance(CIPHER_NAME);
		decryptor.init(Cipher.DECRYPT_MODE, getSecretKey(privateKey, encapsulation),
				new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, iv));

		return new CipherInputStream(encrypted, decryptor);
	}

	private void checkReadBytes(int expectedBytes, int readBytes, String valueName) throws IOException
	{
		if (readBytes != expectedBytes)
			throw new IOException("Could not read " + valueName + ", only read " + readBytes + " bytes instead of "
					+ expectedBytes + " bytes");
	}

	protected abstract SecretKey getSecretKey(PrivateKey privateKey, byte[] encapsulation)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException;
}

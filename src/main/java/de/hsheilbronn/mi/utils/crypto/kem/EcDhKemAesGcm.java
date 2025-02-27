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
import java.util.List;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEM.Decapsulator;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEM.Encapsulator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class EcDhKemAesGcm
{
	/**
	 * KEM name.
	 * 
	 * @see KEM#getInstance(String)
	 */
	public static final String KEM_NAME = "DHKEM";

	/**
	 * Cipher name.
	 * 
	 * @see Cipher#getInstance(String)
	 */
	public static final String CIPHER_NAME = "AES/GCM/NoPadding";

	/**
	 * Algorithm name.
	 * 
	 * @see Encapsulator#encapsulate(int, int, String)
	 * @see Decapsulator#decapsulate(byte[], int, int, String)
	 */
	public static final String ALGORITHM_NAME = "AES";

	/**
	 * To generate random AES initialization vectors.
	 * 
	 * @see #AES_IV_LENGTH
	 */
	public static final SecureRandom SECURE_RANDOM = new SecureRandom();

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

	private final Variant variant;

	/**
	 * With {@link Variant#AES_256}
	 */
	public EcDhKemAesGcm()
	{
		this(Variant.AES_256);
	}

	/**
	 * With given {@link Variant}
	 * 
	 * @param variant
	 *            not <code>null</code>
	 */
	public EcDhKemAesGcm(Variant variant)
	{
		this.variant = Objects.requireNonNull(variant, "variant");
	}

	/**
	 * Encrypts the given {@link InputStream} with an AES session key calculated by DH KEM for the given
	 * {@link PublicKey}. The returned {@link InputStream} has the form [encapsulation length (4 bytes), encapsulation,
	 * AES initialization vector (12 bytes), AES encrypted data].
	 * <p>
	 * Uses {@link #SECURE_RANDOM} to generate random AES initialization vectors.
	 * 
	 * @param data
	 *            not <code>null</code>
	 * @param publicKey
	 *            not <code>null</code>, supported EC key algorithms: X25519, X448, secp256r1, secp384r1 and secp521r1
	 * @return {@link InputStream} of [encapsulation length (4 bytes), encapsulation, iv (12 bytes), encrypted data]
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * 
	 * @see KeyPairGeneratorFactory
	 */
	public InputStream encrypt(InputStream data, PublicKey publicKey) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		return encrypt(data, publicKey, SECURE_RANDOM);
	}

	/**
	 * @param data
	 *            not <code>null</code>
	 * @param publicKey
	 *            not <code>null</code>, supported EC key algorithms: X25519, X448, secp256r1, secp384r1 and secp521r1
	 * @param secureRandom
	 *            not <code>null</code>
	 * @return {@link InputStream} of [encapsulation length (4 bytes), encapsulation, iv (12 bytes), encrypted data]
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @see #SECURE_RANDOM
	 */
	public InputStream encrypt(InputStream data, PublicKey publicKey, SecureRandom secureRandom)
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException
	{
		Objects.requireNonNull(data, "data");
		Objects.requireNonNull(publicKey, "publicKey");

		if (!"EC".equals(publicKey.getAlgorithm()) && !"XDH".equals(publicKey.getAlgorithm()))
			throw new IllegalArgumentException("publicKey.algorithm " + publicKey.getAlgorithm() + " not supported");

		Objects.requireNonNull(secureRandom, "secureRandom");

		KEM kem = KEM.getInstance(KEM_NAME);
		Encapsulator encapsulator = kem.newEncapsulator(publicKey);
		Encapsulated encapsulated = encapsulator.encapsulate(0, variant.size, ALGORITHM_NAME);

		byte[] iv = new byte[AES_IV_LENGTH];
		secureRandom.nextBytes(iv);

		Cipher encryptor = Cipher.getInstance(CIPHER_NAME);
		encryptor.init(Cipher.ENCRYPT_MODE, encapsulated.key(), new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, iv));

		return new SequenceInputStream(Collections.enumeration(List.of(
				new ByteArrayInputStream(ByteBuffer.allocate(4).putInt(encapsulated.encapsulation().length).array()),
				new ByteArrayInputStream(encapsulated.encapsulation()), new ByteArrayInputStream(iv),
				new CipherInputStream(data, encryptor))));
	}

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
	public InputStream decrypt(InputStream encrypted, PrivateKey privateKey)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, DecapsulateException,
			NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		Objects.requireNonNull(encrypted, "encrypted");
		Objects.requireNonNull(privateKey, "privateKey");

		if (!"EC".equals(privateKey.getAlgorithm()) && !"XDH".equals(privateKey.getAlgorithm()))
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

		KEM kem = KEM.getInstance(KEM_NAME);
		Decapsulator decapsulator = kem.newDecapsulator(privateKey);

		Cipher decryptor = Cipher.getInstance(CIPHER_NAME);
		decryptor.init(Cipher.DECRYPT_MODE, decapsulator.decapsulate(encapsulation, 0, variant.size, ALGORITHM_NAME),
				new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, iv));

		return new CipherInputStream(encrypted, decryptor);
	}

	private void checkReadBytes(int expectedBytes, int readBytes, String valueName) throws IOException
	{
		if (readBytes != expectedBytes)
			throw new IOException("Could not read " + valueName + ", only read " + readBytes + " bytes instead of "
					+ expectedBytes + " bytes");
	}
}

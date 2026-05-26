package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.function.BiFunction;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public enum AeadId
{
	AES_128_GCM(0x0001, 16, 12, "AES", "AES/GCM/NoPadding", 128, GCMParameterSpec::new),

	AES_256_GCM(0x0002, 32, 12, "AES", "AES/GCM/NoPadding", 128, GCMParameterSpec::new),

	ChaCha20Poly1305(0x0003, 32, 12, "ChaCha20", "ChaCha20-Poly1305", 128, (_, iV) -> new IvParameterSpec(iV));

	private final int id;
	private final int keyLength;
	private final int ivLength;
	private final String keyAlgorithm;
	private final String cipherAlgorithm;
	private final int authenticationTagLengthBits;
	private final BiFunction<Integer, byte[], AlgorithmParameterSpec> cipherAlgorithmParameterSpecFactory;

	AeadId(int id, int keyLenght, int ivLength, String keyAlgorithm, String cipherAlgorithm,
			int authenticationTagLengthBits,
			BiFunction<Integer, byte[], AlgorithmParameterSpec> cipherAlgorithmParameterSpecFactory)
	{
		this.id = id;
		this.keyLength = keyLenght;
		this.ivLength = ivLength;
		this.keyAlgorithm = keyAlgorithm;
		this.cipherAlgorithm = cipherAlgorithm;
		this.authenticationTagLengthBits = authenticationTagLengthBits;
		this.cipherAlgorithmParameterSpecFactory = cipherAlgorithmParameterSpecFactory;
	}

	public int getId()
	{
		return id;
	}

	public byte[] getIdAsI2osp2Bytes()
	{
		return ByteEncoding.i2osp2(id);
	}

	public int getKeyLength()
	{
		return keyLength;
	}

	public byte[] getKeyLengthAsI2osp2Bytes()
	{
		return ByteEncoding.i2osp2(keyLength);
	}

	public int getIvLength()
	{
		return ivLength;
	}

	public byte[] getIvLengthAsI2osp2Bytes()
	{
		return ByteEncoding.i2osp2(ivLength);
	}

	public int getAuthenticationTagLengthBits()
	{
		return authenticationTagLengthBits;
	}

	public String getKeyAlgorithm()
	{
		return keyAlgorithm;
	}

	public void initEncryptionCipher(Cipher cipher, SecretKey key, byte[] iv)
			throws NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		initCipher(cipher, key, iv, Cipher.ENCRYPT_MODE);
	}

	public void initDecryptionCipher(Cipher cipher, SecretKey key, byte[] iv)
			throws NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		initCipher(cipher, key, iv, Cipher.DECRYPT_MODE);
	}

	private void initCipher(Cipher cipher, SecretKey key, byte[] iv, int mode)
			throws InvalidKeyException, InvalidAlgorithmParameterException
	{
		Objects.requireNonNull(key, "key");
		Objects.requireNonNull(iv, "iv");
		if (ivLength != iv.length)
			throw new IllegalArgumentException("iv.length not " + ivLength);

		AlgorithmParameterSpec spec = cipherAlgorithmParameterSpecFactory.apply(authenticationTagLengthBits, iv);
		cipher.init(mode, key, spec);
	}

	public Cipher toCipher() throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		return Cipher.getInstance(cipherAlgorithm);
	}

	public static AeadId from(byte[] value) throws IllegalArgumentException
	{
		Objects.requireNonNull(value, "value");
		if (value.length != 2)
			throw new IllegalArgumentException("value.length not 2");

		long aeadId = ByteEncoding.os2ip(value);

		if (AES_128_GCM.id == aeadId)
			return AES_128_GCM;
		else if (AES_256_GCM.id == aeadId)
			return AES_256_GCM;
		else if (ChaCha20Poly1305.id == aeadId)
			return ChaCha20Poly1305;
		else
			throw new IllegalArgumentException("AeadId not supported");
	}
}
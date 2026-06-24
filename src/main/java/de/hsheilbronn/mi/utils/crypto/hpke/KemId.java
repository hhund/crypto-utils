package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.AsymmetricKey;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;
import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairValidator;

public enum KemId
{
	DHKEM_P256_HKDF_SHA256(0x0010, 32, 65, DhKemWrapper::new, KeyPairValidator::isSecp256r1,
			KeyPairGeneratorFactory.secp256r1()),

	DHKEM_P384_HKDF_SHA384(0x0011, 48, 97, DhKemWrapper::new, KeyPairValidator::isSecp384r1,
			KeyPairGeneratorFactory.secp384r1()),

	DHKEM_P521_HKDF_SHA512(0x0012, 64, 133, DhKemWrapper::new, KeyPairValidator::isSecp521r1,
			KeyPairGeneratorFactory.secp521r1()),

	DHKEM_X25519_HKDF_SHA256(0x0020, 32, 32, DhKemWrapper::new, KeyPairValidator::isX25519,
			KeyPairGeneratorFactory.x25519()),

	DHKEM_X448_HKDF_SHA512(0x0021, 64, 56, DhKemWrapper::new, KeyPairValidator::isX448, KeyPairGeneratorFactory.x448()),

	/**
	 * RSA-KEM for 1024 Bit RSA keys. KEM ID <code>0xFF10</code> not defined in RFC 9180 and thus not compatible with
	 * other RFC 9180 implementations.<br>
	 * <br>
	 * <b>Insecure, use only for testing.</b>
	 * 
	 * @see RsaKemWrapper
	 */
	RSAKEM_1024_KDF2_SHA256(0xFF10, 32, 128, RsaKemWrapper::new, KeyPairValidator::isRsa1024,
			KeyPairGeneratorFactory.rsa1024()),

	/**
	 * RSA-KEM for 2048 Bit RSA keys. KEM ID <code>0xFF11</code> not defined in RFC 9180 and thus not compatible with
	 * other RFC 9180 implementations.<br>
	 * <br>
	 * Not recommended for production use.
	 * 
	 * @see RsaKemWrapper
	 */
	RSAKEM_2048_KDF2_SHA256(0xFF11, 32, 256, RsaKemWrapper::new, KeyPairValidator::isRsa2048,
			KeyPairGeneratorFactory.rsa2048()),

	/**
	 * RSA-KEM for 3072 Bit RSA keys. KEM ID <code>0xFF12</code> not defined in RFC 9180 and thus not compatible with
	 * other RFC 9180 implementations.<br>
	 * <br>
	 * Not recommended for production use.
	 * 
	 * @see RsaKemWrapper
	 */
	RSAKEM_3072_KDF2_SHA512(0xFF12, 64, 384, RsaKemWrapper::new, KeyPairValidator::isRsa3072,
			KeyPairGeneratorFactory.rsa3072()),

	/**
	 * RSA-KEM for 4096 Bit RSA keys. KEM ID <code>0xFF13</code> not defined in RFC 9180 and thus not compatible with
	 * other RFC 9180 implementations.
	 * 
	 * @see RsaKemWrapper
	 */
	RSAKEM_4096_KDF2_SHA512(0xFF13, 64, 512, RsaKemWrapper::new, KeyPairValidator::isRsa4096,
			KeyPairGeneratorFactory.rsa4096());

	private final int id;
	private final int sharedSecretLength;
	private final int encapsulationLength;
	private final Function<KemId, KemWrapper> kemWrapperFactory;
	private final Predicate<AsymmetricKey> keySupported;
	private final KeyPairGeneratorFactory keyPairGeneratorFactory;

	KemId(int id, int sharedSecretLength, int encapsulationLength, Function<KemId, KemWrapper> kemWrapperFactory,
			Predicate<AsymmetricKey> keySupported, KeyPairGeneratorFactory keyPairGeneratorFactory)
	{
		this.id = id;
		this.sharedSecretLength = sharedSecretLength;
		this.encapsulationLength = encapsulationLength;
		this.kemWrapperFactory = kemWrapperFactory;
		this.keySupported = keySupported;
		this.keyPairGeneratorFactory = keyPairGeneratorFactory;
	}

	public int getId()
	{
		return id;
	}

	public byte[] getIdAsI2osp2Bytes()
	{
		return ByteEncoding.i2osp2(id);
	}

	public int getSharedSecretLength()
	{
		return sharedSecretLength;
	}

	public int getEncapsulationLength()
	{
		return encapsulationLength;
	}

	public KemWrapper toKem()
	{
		return kemWrapperFactory.apply(this);
	}

	public boolean isKeySupported(AsymmetricKey key)
	{
		return keySupported.test(key);
	}

	public KeyPairGeneratorFactory getKeyPairGeneratorFactory()
	{
		return keyPairGeneratorFactory;
	}

	public static KemId from(byte[] value) throws IllegalArgumentException
	{
		Objects.requireNonNull(value, "value");
		if (value.length != 2)
			throw new IllegalArgumentException("value.length not 2");

		long kemId = ByteEncoding.os2ip(value);

		if (DHKEM_P256_HKDF_SHA256.id == kemId)
			return DHKEM_P256_HKDF_SHA256;
		else if (DHKEM_P384_HKDF_SHA384.id == kemId)
			return DHKEM_P384_HKDF_SHA384;
		else if (DHKEM_P521_HKDF_SHA512.id == kemId)
			return DHKEM_P521_HKDF_SHA512;
		else if (DHKEM_X25519_HKDF_SHA256.id == kemId)
			return DHKEM_X25519_HKDF_SHA256;
		else if (DHKEM_X448_HKDF_SHA512.id == kemId)
			return DHKEM_X448_HKDF_SHA512;
		else if (RSAKEM_1024_KDF2_SHA256.id == kemId)
			return RSAKEM_1024_KDF2_SHA256;
		else if (RSAKEM_2048_KDF2_SHA256.id == kemId)
			return RSAKEM_2048_KDF2_SHA256;
		else if (RSAKEM_3072_KDF2_SHA512.id == kemId)
			return RSAKEM_3072_KDF2_SHA512;
		else if (RSAKEM_4096_KDF2_SHA512.id == kemId)
			return RSAKEM_4096_KDF2_SHA512;
		else
			throw new IllegalArgumentException("KemId not supported");
	}
}
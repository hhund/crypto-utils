package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.AlgorithmParameters;
import java.security.AsymmetricKey;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.XECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public enum KemId
{
	DHKEM_P256_HKDF_SHA256(0x0010, 32, 65, DhKemWrapper::new, isEcKey(namedCurve("secp256r1")),
			KeyPairGeneratorFactory.secp256r1()),

	DHKEM_P384_HKDF_SHA384(0x0011, 48, 97, DhKemWrapper::new, isEcKey(namedCurve("secp384r1")),
			KeyPairGeneratorFactory.secp384r1()),

	DHKEM_P521_HKDF_SHA512(0x0012, 64, 133, DhKemWrapper::new, isEcKey(namedCurve("secp521r1")),
			KeyPairGeneratorFactory.secp521r1()),

	DHKEM_X25519_HKDF_SHA256(0x0020, 32, 32, DhKemWrapper::new, isXecKey(NamedParameterSpec.X25519),
			KeyPairGeneratorFactory.x25519()),

	DHKEM_X448_HKDF_SHA512(0x0021, 64, 56, DhKemWrapper::new, isXecKey(NamedParameterSpec.X448),
			KeyPairGeneratorFactory.x448()),

	RSAKEM_1024_KDF2_SHA256(0xFF10, 32, 128, RsaKemWrapper::new, isRsaKey(1024), KeyPairGeneratorFactory.rsa1024()),

	RSAKEM_2048_KDF2_SHA256(0xFF11, 32, 256, RsaKemWrapper::new, isRsaKey(2048), KeyPairGeneratorFactory.rsa2048()),

	RSAKEM_3072_KDF2_SHA512(0xFF12, 64, 384, RsaKemWrapper::new, isRsaKey(3072), KeyPairGeneratorFactory.rsa3072()),

	RSAKEM_4096_KDF2_SHA512(0xFF13, 64, 512, RsaKemWrapper::new, isRsaKey(4096), KeyPairGeneratorFactory.rsa4096());

	private static Predicate<AsymmetricKey> isRsaKey(int length)
	{
		return key -> key instanceof RSAKey rsaKey && rsaKey.getModulus().bitLength() == length;
	}

	private static Predicate<AsymmetricKey> isXecKey(NamedParameterSpec curve)
	{
		return key -> key instanceof XECKey xecKey && xecKey.getParams() instanceof NamedParameterSpec params
				&& curve.getName().equals(params.getName());
	}

	private static Predicate<AsymmetricKey> isEcKey(ECParameterSpec expected)
	{
		return key -> key instanceof ECKey ecKey && matchesCurve(ecKey.getParams(), expected);
	}

	private static boolean matchesCurve(ECParameterSpec actual, ECParameterSpec expected)
	{
		return actual.getCurve().equals(expected.getCurve()) && actual.getGenerator().equals(expected.getGenerator())
				&& actual.getOrder().equals(expected.getOrder()) && actual.getCofactor() == expected.getCofactor();
	}

	private static ECParameterSpec namedCurve(String name)
	{
		try
		{
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec(name));
			return parameters.getParameterSpec(ECParameterSpec.class);
		}
		catch (NoSuchAlgorithmException | InvalidParameterSpecException e)
		{
			throw new RuntimeException(e);
		}
	}

	private final int id;
	private final int sharedSecretLength;
	private final int encapsulationLength;
	private final Function<KemId, KemWrapper> KemWrapperFactory;
	private final Predicate<AsymmetricKey> keySupported;
	private final KeyPairGeneratorFactory keyPairGeneratorFactory;

	KemId(int id, int sharedSecretLength, int encapsulationLength, Function<KemId, KemWrapper> KemWrapperFactory,
			Predicate<AsymmetricKey> keySupported, KeyPairGeneratorFactory keyPairGeneratorFactory)
	{
		this.id = id;
		this.sharedSecretLength = sharedSecretLength;
		this.encapsulationLength = encapsulationLength;
		this.KemWrapperFactory = KemWrapperFactory;
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

	public KemWrapper toKem() throws NoSuchAlgorithmException
	{
		return KemWrapperFactory.apply(this);
	}

	public boolean isKeySupported(AsymmetricKey key)
	{
		return keySupported.test(key);
	}

	public KeyPairGeneratorFactory getKeyPairGeneratorFactory()
	{
		return keyPairGeneratorFactory;
	}

	public static KemId from(byte[] value)
	{
		Objects.requireNonNull(value, "value");
		if (value.length != 2)
			throw new IllegalArgumentException("value.length != 2");

		int kemId = ByteEncoding.os2ip(value);

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
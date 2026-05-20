package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.EnumSet;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class KemIdTest
{
	private static Stream<Arguments> forTestIsKeySupported()
	{
		return Stream.of(
				Arguments.of(KemId.DHKEM_P256_HKDF_SHA256,
						KeyPairGeneratorFactory.secp256r1().initialize().generateKeyPair()),
				Arguments.of(KemId.DHKEM_P384_HKDF_SHA384,
						KeyPairGeneratorFactory.secp384r1().initialize().generateKeyPair()),
				Arguments.of(KemId.DHKEM_P521_HKDF_SHA512,
						KeyPairGeneratorFactory.secp521r1().initialize().generateKeyPair()),
				Arguments.of(KemId.DHKEM_X25519_HKDF_SHA256,
						KeyPairGeneratorFactory.x25519().initialize().generateKeyPair()),
				Arguments.of(KemId.DHKEM_X448_HKDF_SHA512,
						KeyPairGeneratorFactory.x448().initialize().generateKeyPair()),
				Arguments.of(KemId.RSAKEM_1024_KDF2_SHA256,
						KeyPairGeneratorFactory.rsa1024().initialize().generateKeyPair()),
				Arguments.of(KemId.RSAKEM_2048_KDF2_SHA256,
						KeyPairGeneratorFactory.rsa2048().initialize().generateKeyPair()),
				Arguments.of(KemId.RSAKEM_3072_KDF2_SHA512,
						KeyPairGeneratorFactory.rsa3072().initialize().generateKeyPair()),
				Arguments.of(KemId.RSAKEM_4096_KDF2_SHA512,
						KeyPairGeneratorFactory.rsa4096().initialize().generateKeyPair()));
	}

	@ParameterizedTest
	@MethodSource("forTestIsKeySupported")
	void testIsKeySupported(KemId positive, KeyPair pair) throws Exception
	{
		assertTrue(positive.isKeySupported(pair.getPrivate()));
		assertTrue(positive.isKeySupported(pair.getPublic()));

		EnumSet.complementOf(EnumSet.of(positive)).forEach(n ->
		{
			assertFalse(n.isKeySupported(pair.getPrivate()), n.name());
			assertFalse(n.isKeySupported(pair.getPublic()), n.name());
		});
	}

	private static Stream<Arguments> forTestFrom()
	{
		return Stream.of(Arguments.of(KemId.DHKEM_P256_HKDF_SHA256, 0x0010),
				Arguments.of(KemId.DHKEM_P384_HKDF_SHA384, 0x0011), Arguments.of(KemId.DHKEM_P521_HKDF_SHA512, 0x0012),
				Arguments.of(KemId.DHKEM_X25519_HKDF_SHA256, 0x0020),
				Arguments.of(KemId.DHKEM_X448_HKDF_SHA512, 0x0021), Arguments.of(KemId.RSAKEM_1024_KDF2_SHA256, 0xFF10),
				Arguments.of(KemId.RSAKEM_2048_KDF2_SHA256, 0xFF11),
				Arguments.of(KemId.RSAKEM_3072_KDF2_SHA512, 0xFF12),
				Arguments.of(KemId.RSAKEM_4096_KDF2_SHA512, 0xFF13));
	}

	@ParameterizedTest
	@MethodSource("forTestFrom")
	void testFrom(KemId expected, int id) throws Exception
	{
		assertEquals(expected, KemId.from(new byte[] { (byte) (id >>> 8), (byte) id }));
	}

	private static Stream<Arguments> forTestFromInvalid()
	{
		return Stream.of(Arguments.of(null, NullPointerException.class, "value"),
				Arguments.of(new byte[0], IllegalArgumentException.class, "value.length != 2"),
				Arguments.of(new byte[1], IllegalArgumentException.class, "value.length != 2"),
				Arguments.of(new byte[2], IllegalArgumentException.class, "KemId not supported"));
	}

	@ParameterizedTest
	@MethodSource("forTestFromInvalid")
	void testFromInvalid(byte[] invalid, Class<? extends Exception> exceptionClass, String exceptionMessage)
			throws Exception
	{
		Exception exception = assertThrowsExactly(exceptionClass, () -> KemId.from(invalid));
		assertEquals(exceptionMessage, exception.getMessage());
	}

	private static Stream<Arguments> forTestGetter()
	{
		return Stream.of(Arguments.of(0x0010, 32, 65, DhKemWrapper.class, KemId.DHKEM_P256_HKDF_SHA256),
				Arguments.of(0x0011, 48, 97, DhKemWrapper.class, KemId.DHKEM_P384_HKDF_SHA384),
				Arguments.of(0x0012, 64, 133, DhKemWrapper.class, KemId.DHKEM_P521_HKDF_SHA512),
				Arguments.of(0x0020, 32, 32, DhKemWrapper.class, KemId.DHKEM_X25519_HKDF_SHA256),
				Arguments.of(0x0021, 64, 56, DhKemWrapper.class, KemId.DHKEM_X448_HKDF_SHA512),
				Arguments.of(0xFF10, 32, 128, RsaKemWrapper.class, KemId.RSAKEM_1024_KDF2_SHA256),
				Arguments.of(0xFF11, 32, 256, RsaKemWrapper.class, KemId.RSAKEM_2048_KDF2_SHA256),
				Arguments.of(0xFF12, 64, 384, RsaKemWrapper.class, KemId.RSAKEM_3072_KDF2_SHA512),
				Arguments.of(0xFF13, 64, 512, RsaKemWrapper.class, KemId.RSAKEM_4096_KDF2_SHA512));
	}

	@ParameterizedTest
	@MethodSource("forTestGetter")
	void testGetter(int expectedId, int expectedSharedSecretLength, int expectedEncapsulationLength,
			Class<? extends KemWrapper> expectedKemWrapperClass, KemId kemId) throws Exception
	{
		assertEquals(expectedId, kemId.getId());
		assertArrayEquals(new byte[] { (byte) (expectedId >>> 8), (byte) expectedId }, kemId.getIdAsI2osp2Bytes());
		assertEquals(expectedSharedSecretLength, kemId.getSharedSecretLength());
		assertEquals(expectedEncapsulationLength, kemId.getEncapsulationLength());

		KemWrapper kem = kemId.toKem();
		assertNotNull(kem);
		assertEquals(expectedKemWrapperClass, kem.getClass());
	}
}

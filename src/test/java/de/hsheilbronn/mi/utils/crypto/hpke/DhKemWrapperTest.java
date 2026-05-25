package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.stream.Stream;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class DhKemWrapperTest
{
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private static Stream<Arguments> forTestConstructor()
	{
		return EnumSet.complementOf(DhKemWrapper.DH_KEMS).stream().map(Arguments::of);
	}

	@ParameterizedTest
	@MethodSource("forTestConstructor")
	void testConstructor(KemId kemId) throws Exception
	{
		IllegalArgumentException e = assertThrowsExactly(IllegalArgumentException.class, () -> new DhKemWrapper(kemId));
		assertEquals("KemId " + kemId.name() + " not supported", e.getMessage());
	}

	private static Stream<Arguments> forTestTruncatedEnc()
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
						KeyPairGeneratorFactory.x448().initialize().generateKeyPair()));
	}

	@ParameterizedTest
	@MethodSource("forTestTruncatedEnc")
	void testTruncatedEnc(KemId kemId, KeyPair keyPair) throws Exception
	{
		DhKemWrapper w = new DhKemWrapper(kemId);
		Encapsulated encapsulated = w.getEncapsulated(keyPair.getPublic(), SECURE_RANDOM);

		assertNotNull(encapsulated);

		SecretKey sKey = encapsulated.key();
		assertNotNull(sKey);
		assertEquals("Generic", sKey.getAlgorithm());
		assertNotNull(sKey.getEncoded());

		byte[] encapsulation = encapsulated.encapsulation();
		assertNotNull(encapsulation);
		assertEquals(kemId.getEncapsulationLength(), encapsulation.length);

		for (int i = 0; i <= encapsulation.length; i++)
		{
			try
			{
				w.getSharedSecret(keyPair.getPrivate(), Arrays.copyOfRange(encapsulation, 0, encapsulation.length - i));
				assertEquals(0, i); // only not truncated stream ok
			}
			catch (IllegalStateException e)
			{
				assertEquals("encapsulation.length not " + kemId.getEncapsulationLength(), e.getMessage());
			}
		}
	}

	private static Stream<Arguments> forTestModifiedDheEnc()
	{
		return Stream.of(
				Arguments.of(KemId.DHKEM_P256_HKDF_SHA256,
						KeyPairGeneratorFactory.secp256r1().initialize().generateKeyPair()),
				Arguments.of(KemId.DHKEM_P384_HKDF_SHA384,
						KeyPairGeneratorFactory.secp384r1().initialize().generateKeyPair()),
				Arguments.of(KemId.DHKEM_P521_HKDF_SHA512,
						KeyPairGeneratorFactory.secp521r1().initialize().generateKeyPair()));
	}

	@ParameterizedTest
	@MethodSource("forTestModifiedDheEnc")
	void testModifiedDheEnc(KemId kemId, KeyPair keyPair) throws Exception
	{
		DhKemWrapper w = new DhKemWrapper(kemId);
		Encapsulated encapsulated = w.getEncapsulated(keyPair.getPublic(), SECURE_RANDOM);

		assertNotNull(encapsulated);

		SecretKey sKey = encapsulated.key();
		assertNotNull(sKey);
		assertEquals("Generic", sKey.getAlgorithm());
		assertNotNull(sKey.getEncoded());

		byte[] encapsulation = encapsulated.encapsulation();
		assertNotNull(encapsulation);
		assertEquals(kemId.getEncapsulationLength(), encapsulation.length);

		assertEquals(encapsulation[0], (byte) 0x04);

		encapsulation[0] ^= 0x01;
		DecapsulateException e = assertThrows(DecapsulateException.class,
				() -> w.getSharedSecret(keyPair.getPrivate(), encapsulation));
		assertEquals("Cannot decapsulate", e.getMessage());
		assertNotNull(e.getCause());
		assertEquals(IOException.class, e.getCause().getClass());

		encapsulation[0] = (byte) 0x04;
		encapsulation[1] ^= 0x01;
		e = assertThrows(DecapsulateException.class, () -> w.getSharedSecret(keyPair.getPrivate(), encapsulation));
		assertEquals("Cannot decapsulate", e.getMessage());
		assertNotNull(e.getCause());
		assertEquals(InvalidKeyException.class, e.getCause().getClass());
	}

	private static Stream<Arguments> forTestModifiedDhxEnc()
	{
		return Stream.of(
				Arguments.of(KemId.DHKEM_X25519_HKDF_SHA256,
						KeyPairGeneratorFactory.x25519().initialize().generateKeyPair()),
				Arguments.of(KemId.DHKEM_X448_HKDF_SHA512,
						KeyPairGeneratorFactory.x448().initialize().generateKeyPair()));
	}

	@ParameterizedTest
	@MethodSource("forTestModifiedDhxEnc")
	void testModifiedDhxEnc(KemId kemId, KeyPair keyPair) throws Exception
	{
		DhKemWrapper w = new DhKemWrapper(kemId);
		Encapsulated encapsulated = w.getEncapsulated(keyPair.getPublic(), SECURE_RANDOM);

		assertNotNull(encapsulated);

		SecretKey sKey = encapsulated.key();
		assertNotNull(sKey);
		assertEquals("Generic", sKey.getAlgorithm());
		assertNotNull(sKey.getEncoded());

		byte[] encapsulation = encapsulated.encapsulation();
		assertNotNull(encapsulation);
		assertEquals(kemId.getEncapsulationLength(), encapsulation.length);

		encapsulation[0] ^= 0x01;

		for (int i = 0; i < encapsulation.length; i++)
		{
			encapsulation[i] ^= 0x01;
			SecretKey sharedSecret = w.getSharedSecret(keyPair.getPrivate(), encapsulation);

			assertNotSame(sKey, sharedSecret);
		}
	}
}

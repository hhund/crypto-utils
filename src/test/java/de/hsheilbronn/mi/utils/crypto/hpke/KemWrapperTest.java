package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.stream.Stream;

import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class KemWrapperTest
{
	private static final SecureRandom SECURE_RANDDOM = new SecureRandom();

	private static Stream<Arguments> forTestKem()
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
	@MethodSource("forTestKem")
	void testKem(KemId kemId, KeyPair keyPair) throws Exception
	{
		KemWrapper kem = kemId.toKem();
		assertNotNull(kem);

		Encapsulated encapsulated = kem.getEncapsulated(keyPair.getPublic(), SECURE_RANDDOM);
		assertNotNull(encapsulated);

		byte[] encapsulation = encapsulated.encapsulation();
		assertNotNull(encapsulation);
		assertEquals(kemId.getEncapsulationLength(), encapsulation.length);

		SecretKey sharedSecretSender = encapsulated.key();
		assertNotNull(sharedSecretSender);
		assertEquals(kemId.getSharedSecretLength(), sharedSecretSender.getEncoded().length);

		SecretKey sharedSecretReceiver = kem.getSharedSecret(keyPair.getPrivate(), encapsulation);
		assertNotNull(sharedSecretReceiver);
		assertEquals(kemId.getSharedSecretLength(), sharedSecretReceiver.getEncoded().length);

		assertArrayEquals(sharedSecretSender.getEncoded(), sharedSecretReceiver.getEncoded());
	}
}

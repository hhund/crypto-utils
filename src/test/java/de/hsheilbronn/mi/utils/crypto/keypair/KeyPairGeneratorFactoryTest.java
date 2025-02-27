package de.hsheilbronn.mi.utils.crypto.keypair;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.XECPrivateKey;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KeyPairGeneratorFactoryTest
{
	private static Stream<Arguments> forTestGenerateKeyPair()
	{
		return Stream.of(Arguments.of(KeyPairGeneratorFactory.ed25519(), EdECPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.ed448(), EdECPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.rsa1024(), RSAPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.rsa2048(), RSAPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.rsa3072(), RSAPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.rsa4096(), RSAPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.rsa(1024 * 5), RSAPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.secp256r1(), ECPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.secp384r1(), ECPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.secp521r1(), ECPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.x25519(), XECPrivateKey.class),
				Arguments.of(KeyPairGeneratorFactory.x448(), XECPrivateKey.class));
	}

	@ParameterizedTest
	@MethodSource("forTestGenerateKeyPair")
	void testGenerateKeyPair(KeyPairGeneratorFactory factory, Class<? extends PrivateKey> privateKeyType)
			throws Exception
	{
		KeyPairGenerator generator = factory.initialize();
		assertNotNull(generator);

		KeyPair keyPair = generator.generateKeyPair();
		assertNotNull(keyPair);

		assertTrue(privateKeyType.isInstance(keyPair.getPrivate()),
				"Class name: " + keyPair.getPrivate().getClass().getName());
	}

	@Test
	void testGenerateKeyPairIllegalRsaKeySize()
	{
		assertThrowsExactly(IllegalArgumentException.class, () -> KeyPairGeneratorFactory.rsa(512));
		assertThrowsExactly(IllegalArgumentException.class, () -> KeyPairGeneratorFactory.rsa(1024 + 1));
		assertThrowsExactly(IllegalArgumentException.class, () -> KeyPairGeneratorFactory.rsa(1024 - 1));
	}
}

package de.hsheilbronn.mi.utils.crypto.keypair;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KeyPairValidatorTest
{
	private static Stream<Arguments> forTestMatches()
	{
		PrivateKey privateEd25519 = KeyPairGeneratorFactory.ed25519().initialize().generateKeyPair().getPrivate();
		PublicKey publicRsa1024 = KeyPairGeneratorFactory.rsa1024().initialize().generateKeyPair().getPublic();

		return Stream.concat(Stream.of(KeyPairGeneratorFactory.ed25519(), KeyPairGeneratorFactory.ed448(),
				KeyPairGeneratorFactory.rsa1024(), KeyPairGeneratorFactory.rsa2048(), KeyPairGeneratorFactory.rsa3072(),
				KeyPairGeneratorFactory.rsa4096(), KeyPairGeneratorFactory.secp256r1(),
				KeyPairGeneratorFactory.secp384r1(), KeyPairGeneratorFactory.secp521r1(),
				KeyPairGeneratorFactory.x25519(), KeyPairGeneratorFactory.x448()).flatMap(f ->
				{
					KeyPair kp1 = f.initialize().generateKeyPair();
					KeyPair kp2 = f.initialize().generateKeyPair();
					return Stream.of(Arguments.of(true, kp1.getPublic(), kp1.getPrivate()),
							Arguments.of(false, kp2.getPublic(), kp1.getPrivate()),
							Arguments.of(false, kp1.getPublic(), kp2.getPrivate()),
							Arguments.of(false, kp1.getPublic(), null), Arguments.of(false, null, kp2.getPrivate()));
				}), Stream.of(Arguments.of(false, publicRsa1024, privateEd25519)));

	}

	@ParameterizedTest
	@MethodSource("forTestMatches")
	public void testMatches(boolean expected, PublicKey publicKey, PrivateKey privateKey) throws Exception
	{
		assertEquals(expected, KeyPairValidator.matches(privateKey, publicKey));
	}
}

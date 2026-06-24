package de.hsheilbronn.mi.utils.crypto.keypair;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.AsymmetricKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KeyPairValidatorTest
{
	private static Stream<Arguments> forTestMatches() throws Exception
	{
		PrivateKey privateEd25519 = KeyPairGeneratorFactory.ed25519().initialize().generateKeyPair().getPrivate();
		PublicKey publicRsa1024 = KeyPairGeneratorFactory.rsa1024().initialize().generateKeyPair().getPublic();

		KeyPair rsa1024WithNonCrtPrivateKey = generateRsa1024WithNonCrtPrivateKey();

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
				}), Stream.of(Arguments.of(false, publicRsa1024, privateEd25519), Arguments.of(true,
						rsa1024WithNonCrtPrivateKey.getPublic(), rsa1024WithNonCrtPrivateKey.getPrivate())));
	}

	private static KeyPair generateRsa1024WithNonCrtPrivateKey() throws Exception
	{
		KeyPair keyPair = KeyPairGeneratorFactory.rsa1024().initialize().generateKeyPair();
		RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) keyPair.getPrivate();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey nonCrtKey = keyFactory
				.generatePrivate(new RSAPrivateKeySpec(crtKey.getModulus(), crtKey.getPrivateExponent()));

		return new KeyPair(keyPair.getPublic(), nonCrtKey);
	}

	@ParameterizedTest
	@MethodSource("forTestMatches")
	public void testMatches(boolean expected, PublicKey publicKey, PrivateKey privateKey) throws Exception
	{
		assertEquals(expected, KeyPairValidator.matches(privateKey, publicKey));
	}

	private static Stream<Arguments> forTestIsKey() throws Exception
	{
		List<KeyPair> keyPairs = Stream.of(KeyPairGeneratorFactory.ed25519(), KeyPairGeneratorFactory.ed448(),
				KeyPairGeneratorFactory.rsa1024(), KeyPairGeneratorFactory.rsa2048(), KeyPairGeneratorFactory.rsa3072(),
				KeyPairGeneratorFactory.rsa4096(), KeyPairGeneratorFactory.secp256r1(),
				KeyPairGeneratorFactory.secp384r1(), KeyPairGeneratorFactory.secp521r1(),
				KeyPairGeneratorFactory.x25519(), KeyPairGeneratorFactory.x448())
				.map(f -> f.initialize().generateKeyPair()).toList();

		return IntStream.range(0, keyPairs.size()).boxed().mapMulti((i, consumer) ->
		{
			KeyPair keyPair = keyPairs.get(i);
			boolean[] expected = new boolean[keyPairs.size()];
			expected[i] = true;

			consumer.accept(Arguments.of(keyPair.getPrivate(), expected));
			consumer.accept(Arguments.of(keyPair.getPublic(), expected));
		});
	}

	@ParameterizedTest
	@MethodSource("forTestIsKey")
	void testIsKey(AsymmetricKey key, boolean[] expected) throws Exception
	{
		assertEquals(expected[0], KeyPairValidator.isEd25519(key));
		assertEquals(expected[1], KeyPairValidator.isEd448(key));
		assertEquals(expected[2], KeyPairValidator.isRsa1024(key));
		assertEquals(expected[3], KeyPairValidator.isRsa2048(key));
		assertEquals(expected[4], KeyPairValidator.isRsa3072(key));
		assertEquals(expected[5], KeyPairValidator.isRsa4096(key));
		assertEquals(expected[6], KeyPairValidator.isSecp256r1(key));
		assertEquals(expected[7], KeyPairValidator.isSecp384r1(key));
		assertEquals(expected[8], KeyPairValidator.isSecp521r1(key));
		assertEquals(expected[9], KeyPairValidator.isX25519(key));
		assertEquals(expected[10], KeyPairValidator.isX448(key));
	}
}

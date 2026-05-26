package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class AbstractKemWrapperTest
{
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private static AbstractKemWrapper createTestWrapper(KemId kemId, int testEncapsulationLength,
			int testSharedSecretLength)
	{
		return new AbstractKemWrapper(kemId)
		{
			@Override
			protected Encapsulated doGetEncapsulated(PublicKey publicKey, SecureRandom secureRandom,
					int sharedSecretLength) throws NoSuchAlgorithmException, InvalidKeyException
			{
				return new Encapsulated(createKey(testSharedSecretLength), new byte[testEncapsulationLength], null);
			}

			@Override
			protected SecretKey doGetSharedSecret(PrivateKey privateKey, byte[] encapsulation, int sharedSecretLength)
					throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException
			{
				return createKey(testSharedSecretLength);
			}

			private SecretKeySpec createKey(int sharedSecretLength)
			{
				return new SecretKeySpec(new byte[sharedSecretLength], "Generic");
			}
		};
	}

	@Test
	void testKeyNotSupported() throws Exception
	{
		KemId kemId = KemId.DHKEM_P256_HKDF_SHA256;
		AbstractKemWrapper wrapper = createTestWrapper(kemId, kemId.getEncapsulationLength(),
				kemId.getSharedSecretLength());
		KeyPair notOkKeyPair = KeyPairGeneratorFactory.secp384r1().initialize().generateKeyPair();
		KeyPair okKeyPair = kemId.getKeyPairGeneratorFactory().initialize().generateKeyPair();

		assertDoesNotThrow(() -> wrapper.getEncapsulated(okKeyPair.getPublic(), SECURE_RANDOM));
		KeyNotSupportedException e = assertThrowsExactly(KeyNotSupportedException.class,
				() -> wrapper.getEncapsulated(notOkKeyPair.getPublic(), SECURE_RANDOM));
		assertEquals("publicKey not supported", e.getMessage());

		assertDoesNotThrow(
				() -> wrapper.getSharedSecret(okKeyPair.getPrivate(), new byte[kemId.getEncapsulationLength()]));
		e = assertThrowsExactly(KeyNotSupportedException.class,
				() -> wrapper.getSharedSecret(notOkKeyPair.getPrivate(), new byte[kemId.getEncapsulationLength()]));
		assertEquals("privateKey not supported", e.getMessage());
	}

	@Test
	void testBadEncapsulationLength() throws Exception
	{
		KemId kemId = KemId.DHKEM_P256_HKDF_SHA256;
		KeyPair okKeyPair = kemId.getKeyPairGeneratorFactory().initialize().generateKeyPair();

		assertDoesNotThrow(() -> createTestWrapper(kemId, kemId.getEncapsulationLength(), kemId.getSharedSecretLength())
				.getEncapsulated(okKeyPair.getPublic(), SECURE_RANDOM));
		IllegalStateException isE = assertThrowsExactly(IllegalStateException.class,
				() -> createTestWrapper(kemId, 0, kemId.getSharedSecretLength()).getEncapsulated(okKeyPair.getPublic(),
						SECURE_RANDOM));
		assertEquals("encapsulation.length not " + kemId.getEncapsulationLength(), isE.getMessage());

		assertDoesNotThrow(() -> createTestWrapper(kemId, kemId.getEncapsulationLength(), kemId.getSharedSecretLength())
				.getSharedSecret(okKeyPair.getPrivate(), new byte[kemId.getEncapsulationLength()]));

		IllegalStateException iaE = assertThrowsExactly(IllegalStateException.class,
				() -> createTestWrapper(kemId, kemId.getEncapsulationLength(), kemId.getSharedSecretLength())
						.getSharedSecret(okKeyPair.getPrivate(), new byte[0]));
		assertEquals("encapsulation.length not " + kemId.getEncapsulationLength(), iaE.getMessage());
	}

	@Test
	void testBadSharedSecretLength() throws Exception
	{
		KemId kemId = KemId.DHKEM_P256_HKDF_SHA256;
		KeyPair okKeyPair = kemId.getKeyPairGeneratorFactory().initialize().generateKeyPair();
		assertDoesNotThrow(() -> createTestWrapper(kemId, kemId.getEncapsulationLength(), kemId.getSharedSecretLength())
				.getEncapsulated(okKeyPair.getPublic(), SECURE_RANDOM));
		IllegalStateException isE = assertThrowsExactly(IllegalStateException.class,
				() -> createTestWrapper(kemId, kemId.getEncapsulationLength(), kemId.getSharedSecretLength() - 1)
						.getEncapsulated(okKeyPair.getPublic(), SECURE_RANDOM));
		assertEquals("sharedSecret.length not " + kemId.getSharedSecretLength(), isE.getMessage());

		assertDoesNotThrow(() -> createTestWrapper(kemId, kemId.getEncapsulationLength(), kemId.getSharedSecretLength())
				.getSharedSecret(okKeyPair.getPrivate(), new byte[kemId.getEncapsulationLength()]));

		IllegalStateException iaE = assertThrowsExactly(IllegalStateException.class,
				() -> createTestWrapper(kemId, kemId.getEncapsulationLength(), kemId.getSharedSecretLength() - 1)
						.getSharedSecret(okKeyPair.getPrivate(), new byte[kemId.getEncapsulationLength()]));
		assertEquals("sharedSecret.length not " + kemId.getSharedSecretLength(), iaE.getMessage());
	}
}

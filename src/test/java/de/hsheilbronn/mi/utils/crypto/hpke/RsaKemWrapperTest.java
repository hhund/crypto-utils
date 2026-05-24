package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.util.EnumSet;
import java.util.stream.Stream;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.kems.RSAKEMExtractor;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class RsaKemWrapperTest
{
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private static Stream<Arguments> forTestConstructor()
	{
		return EnumSet.complementOf(EnumSet.of(KemId.RSAKEM_1024_KDF2_SHA256, KemId.RSAKEM_2048_KDF2_SHA256,
				KemId.RSAKEM_3072_KDF2_SHA512, KemId.RSAKEM_4096_KDF2_SHA512)).stream().map(Arguments::of);
	}

	@ParameterizedTest
	@MethodSource("forTestConstructor")
	void testConstructor(KemId kemId) throws Exception
	{
		IllegalArgumentException e = assertThrowsExactly(IllegalArgumentException.class,
				() -> new RsaKemWrapper(kemId));
		assertEquals("KemId " + kemId.name() + " not supported", e.getMessage());
	}

	private static Stream<Arguments> rsaKemVariants()
	{
		KDF2BytesGenerator kdf2Sha256 = new KDF2BytesGenerator(new SHA256Digest());
		KDF2BytesGenerator kdf2Sha512 = new KDF2BytesGenerator(new SHA512Digest());

		return Stream.of(
				Arguments.of(KemId.RSAKEM_1024_KDF2_SHA256,
						KeyPairGeneratorFactory.rsa1024().initialize().generateKeyPair(), kdf2Sha256),
				Arguments.of(KemId.RSAKEM_2048_KDF2_SHA256,
						KeyPairGeneratorFactory.rsa2048().initialize().generateKeyPair(), kdf2Sha256),
				Arguments.of(KemId.RSAKEM_3072_KDF2_SHA512,
						KeyPairGeneratorFactory.rsa3072().initialize().generateKeyPair(), kdf2Sha512),
				Arguments.of(KemId.RSAKEM_4096_KDF2_SHA512,
						KeyPairGeneratorFactory.rsa4096().initialize().generateKeyPair(), kdf2Sha512));
	}

	@ParameterizedTest
	@MethodSource("rsaKemVariants")
	void testAgainstBouncyCastleImplementation(KemId kemId, KeyPair keyPair, DerivationFunction kdf) throws Exception
	{
		RsaKemWrapper w = new RsaKemWrapper(kemId);
		Encapsulated encapsulated = w.getEncapsulated(keyPair.getPublic(), SECURE_RANDOM);

		assertNotNull(encapsulated);

		SecretKey sKey = encapsulated.key();
		assertNotNull(sKey);
		assertEquals("Generic", sKey.getAlgorithm());
		assertNotNull(sKey.getEncoded());

		byte[] encapsulation = encapsulated.encapsulation();
		assertNotNull(encapsulation);
		assertEquals(kemId.getEncapsulationLength(), encapsulation.length);

		SecretKey rKey = w.getSharedSecret(keyPair.getPrivate(), encapsulation);
		assertNotNull(rKey);
		assertEquals("Generic", rKey.getAlgorithm());
		assertNotNull(rKey.getEncoded());

		assertEquals(sKey, rKey);

		SecretKey rKeyBC = bouncyCastledoGetSecretKey(keyPair.getPrivate(), encapsulation,
				kemId.getSharedSecretLength(), kdf);
		assertNotNull(rKeyBC);
		assertEquals("Generic", rKeyBC.getAlgorithm());
		assertNotNull(rKeyBC.getEncoded());

		assertEquals(sKey, rKeyBC);
	}

	private SecretKey bouncyCastledoGetSecretKey(PrivateKey privateKey, byte[] encapsulation, int sharedSecretLength,
			DerivationFunction kdf) throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException
	{
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;

		RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(true, rsaPrivateKey.getModulus(),
				rsaPrivateKey.getPrivateExponent());

		RSAKEMExtractor decapsulator = new RSAKEMExtractor(rsaKeyParameters, sharedSecretLength, kdf);

		return new SecretKeySpec(decapsulator.extractSecret(encapsulation), "Generic");
	}

	@ParameterizedTest
	@MethodSource("rsaKemVariants")
	void testTruncatedEnc(KemId kemId, KeyPair keyPair, DerivationFunction kdf) throws Exception
	{
		RsaKemWrapper w = new RsaKemWrapper(kemId);
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
			catch (DecapsulateException e)
			{
				assertEquals("encapsulation.length not " + kemId.getEncapsulationLength(), e.getMessage());
			}
		}
	}

	@ParameterizedTest
	@MethodSource("rsaKemVariants")
	void testModifiedEnc(KemId kemId, KeyPair keyPair, DerivationFunction kdf) throws Exception
	{
		RsaKemWrapper w = new RsaKemWrapper(kemId);
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
		SecretKey sharedSecret = w.getSharedSecret(keyPair.getPrivate(), encapsulation);

		assertNotSame(sKey, sharedSecret);
	}
}

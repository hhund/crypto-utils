package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.security.AlgorithmParameters;
import java.security.spec.InvalidParameterSpecException;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.util.Arrays;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class AeadIdTest
{
	private static Stream<Arguments> forTestFrom()
	{
		return Stream.of(Arguments.of(AeadId.AES_128_GCM, 0x0001), Arguments.of(AeadId.AES_256_GCM, 0x0002),
				Arguments.of(AeadId.ChaCha20Poly1305, 0x0003));
	}

	@ParameterizedTest
	@MethodSource("forTestFrom")
	void testFrom(AeadId expected, int id) throws Exception
	{
		assertEquals(expected, AeadId.from(new byte[] { (byte) (id >>> 8), (byte) id }));
	}

	private static Stream<Arguments> forTestFromInvalid()
	{
		return Stream.of(Arguments.of(null, NullPointerException.class, "value"),
				Arguments.of(new byte[0], IllegalArgumentException.class, "value.length not 2"),
				Arguments.of(new byte[1], IllegalArgumentException.class, "value.length not 2"),
				Arguments.of(new byte[2], IllegalArgumentException.class, "AeadId not supported"));
	}

	@ParameterizedTest
	@MethodSource("forTestFromInvalid")
	void testFromInvalid(byte[] invalid, Class<? extends Exception> exceptionClass, String exceptionMessage)
			throws Exception
	{
		Exception exception = assertThrowsExactly(exceptionClass, () -> AeadId.from(invalid));
		assertEquals(exceptionMessage, exception.getMessage());
	}

	@FunctionalInterface
	private static interface CipherAlgorithmParametersEvaluator
	{
		void evaluate(AlgorithmParameters params, int expectedAuthTagLengthBits, byte[] expectedIv)
				throws InvalidParameterSpecException;
	}

	private static Stream<Arguments> forTestGetter()
	{
		CipherAlgorithmParametersEvaluator gcmEvaluator = (params, expectedAuthTagLengthBits, expectedIv) ->
		{
			GCMParameterSpec parameterSpec = params.getParameterSpec(GCMParameterSpec.class);
			assertNotNull(parameterSpec);
			assertEquals(expectedAuthTagLengthBits, parameterSpec.getTLen());
			assertArrayEquals(expectedIv, parameterSpec.getIV());
		};

		CipherAlgorithmParametersEvaluator chaCha20Poly1305Evaluator = (params, _, expectedIv) ->
		{
			IvParameterSpec parameterSpec = params.getParameterSpec(IvParameterSpec.class);
			assertArrayEquals(expectedIv, parameterSpec.getIV());
		};

		return Stream.of(
				Arguments.of(0x0001, "AES", "AES/GCM/NoPadding", 16, 12, 128, "GCM", gcmEvaluator, AeadId.AES_128_GCM),
				Arguments.of(0x0002, "AES", "AES/GCM/NoPadding", 32, 12, 128, "GCM", gcmEvaluator, AeadId.AES_256_GCM),
				Arguments.of(0x0003, "ChaCha20", "ChaCha20-Poly1305", 32, 12, 128, "ChaCha20-Poly1305",
						chaCha20Poly1305Evaluator, AeadId.ChaCha20Poly1305));
	}

	@ParameterizedTest
	@MethodSource("forTestGetter")
	void testGetter(int expectedId, String expectedKeyAlgorithm, String expectedCipherAlgorithm, int expectedKeyLength,
			int expectedIvLength, int expectedAuthTagLengthBits, String cipherParameterAlgorithmName,
			CipherAlgorithmParametersEvaluator cipherAlgorithmParametersEvaluator, AeadId aeadId) throws Exception
	{
		assertEquals(expectedId, aeadId.getId());
		assertArrayEquals(new byte[] { (byte) (expectedId >>> 8), (byte) expectedId }, aeadId.getIdAsI2osp2Bytes());
		assertEquals(expectedKeyAlgorithm, aeadId.getKeyAlgorithm());
		assertEquals(expectedKeyLength, aeadId.getKeyLength());
		assertArrayEquals(new byte[] { (byte) (expectedKeyLength >>> 8), (byte) expectedKeyLength },
				aeadId.getKeyLengthAsI2osp2Bytes());
		assertEquals(expectedIvLength, aeadId.getIvLength());
		assertArrayEquals(new byte[] { (byte) (expectedIvLength >>> 8), (byte) expectedIvLength },
				aeadId.getIvLengthAsI2osp2Bytes());
		assertEquals(expectedAuthTagLengthBits, aeadId.getAuthenticationTagLengthBits());

		Cipher cipher = aeadId.toCipher();
		assertNotNull(cipher);
		assertEquals(expectedCipherAlgorithm, cipher.getAlgorithm());

		KeyGenerator keyGen = KeyGenerator.getInstance(aeadId.getKeyAlgorithm());
		keyGen.init(aeadId.getKeyLength() * 8);
		SecretKey secretKey = keyGen.generateKey();
		byte[] iv = new byte[aeadId.getIvLength()];
		Arrays.fill(iv, (byte) 0xAB);

		assertDoesNotThrow(() -> aeadId.initEncryptionCipher(cipher, secretKey, iv));
		assertNotNull(cipher.getIV());
		assertArrayEquals(iv, cipher.getIV());
		assertEquals(cipherParameterAlgorithmName, cipher.getParameters().getAlgorithm());
		IllegalArgumentException e = assertThrowsExactly(IllegalArgumentException.class,
				() -> aeadId.initEncryptionCipher(cipher, secretKey, new byte[0]));
		assertEquals("iv.length not " + aeadId.getIvLength(), e.getMessage());

		cipherAlgorithmParametersEvaluator.evaluate(cipher.getParameters(), expectedAuthTagLengthBits, iv);

		assertDoesNotThrow(() -> aeadId.initDecryptionCipher(cipher, secretKey, iv));
		assertNotNull(cipher.getIV());
		assertArrayEquals(iv, cipher.getIV());
		assertEquals(cipherParameterAlgorithmName, cipher.getParameters().getAlgorithm());
		e = assertThrowsExactly(IllegalArgumentException.class,
				() -> aeadId.initDecryptionCipher(cipher, secretKey, new byte[0]));
		assertEquals("iv.length not " + aeadId.getIvLength(), e.getMessage());

		cipherAlgorithmParametersEvaluator.evaluate(cipher.getParameters(), expectedAuthTagLengthBits, iv);
	}
}

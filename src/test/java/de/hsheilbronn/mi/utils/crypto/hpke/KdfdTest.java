package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.util.stream.Stream;

import javax.crypto.KDF;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KdfdTest
{
	private static Stream<Arguments> forTestFrom()
	{
		return Stream.of(Arguments.of(KdfId.HKDF_SHA256, 0x0001), Arguments.of(KdfId.HKDF_SHA384, 0x0002),
				Arguments.of(KdfId.HKDF_SHA512, 0x0003));
	}

	@ParameterizedTest
	@MethodSource("forTestFrom")
	void testFrom(KdfId expected, int id) throws Exception
	{
		assertEquals(expected, KdfId.from(new byte[] { (byte) (id >>> 8), (byte) id }));
	}

	private static Stream<Arguments> forTestFromInvalid()
	{
		return Stream.of(Arguments.of(null, NullPointerException.class, "value"),
				Arguments.of(new byte[0], IllegalArgumentException.class, "value.length != 2"),
				Arguments.of(new byte[1], IllegalArgumentException.class, "value.length != 2"),
				Arguments.of(new byte[2], IllegalArgumentException.class, "KdfId not supported"));
	}

	@ParameterizedTest
	@MethodSource("forTestFromInvalid")
	void testFromInvalid(byte[] invalid, Class<? extends Exception> exceptionClass, String exceptionMessage)
			throws Exception
	{
		Exception exception = assertThrowsExactly(exceptionClass, () -> KdfId.from(invalid));
		assertEquals(exceptionMessage, exception.getMessage());
	}

	private static Stream<Arguments> forTestGetter()
	{
		return Stream.of(Arguments.of(0x0001, "HKDF-SHA256", KdfId.HKDF_SHA256),
				Arguments.of(0x0002, "HKDF-SHA384", KdfId.HKDF_SHA384),
				Arguments.of(0x0003, "HKDF-SHA512", KdfId.HKDF_SHA512));
	}

	@ParameterizedTest
	@MethodSource("forTestGetter")
	void testGetter(int expectedId, String expectedAlgorithm, KdfId kdfId) throws Exception
	{
		assertEquals(expectedId, kdfId.getId());
		assertArrayEquals(new byte[] { (byte) (expectedId >>> 8), (byte) expectedId }, kdfId.getIdAsI2osp2Bytes());
		assertEquals(expectedAlgorithm, kdfId.getAlgorithm());

		KDF kdf = kdfId.toKdf();
		assertNotNull(kdf);
		assertEquals(expectedAlgorithm, kdf.getAlgorithm());
	}
}

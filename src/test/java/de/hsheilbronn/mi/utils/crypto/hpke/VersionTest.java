package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class VersionTest
{
	private static Stream<Arguments> forTestFrom()
	{
		return Stream.of(Arguments.of(Version.V1, 0x01));
	}

	@ParameterizedTest
	@MethodSource("forTestFrom")
	void testFrom(Version expected, int id) throws Exception
	{
		assertEquals(expected, Version.from((byte) id));
	}

	private static Stream<Arguments> forTestFromInvalid()
	{
		return Stream.of(Arguments.of(0x02, IllegalArgumentException.class, "Version not supported"),
				Arguments.of(0xFF, IllegalArgumentException.class, "Version not supported"));
	}

	@ParameterizedTest
	@MethodSource("forTestFromInvalid")
	void testFromInvalid(int invalid, Class<? extends Exception> exceptionClass, String exceptionMessage)
			throws Exception
	{
		Exception exception = assertThrowsExactly(exceptionClass, () -> Version.from((byte) invalid));
		assertEquals(exceptionMessage, exception.getMessage());
	}

	private static Stream<Arguments> forTestGetter()
	{
		return Stream.of(Arguments.of(0x01, Version.V1));
	}

	@ParameterizedTest
	@MethodSource("forTestGetter")
	void testGetter(int expectedValue, Version version) throws Exception
	{
		assertEquals(expectedValue, version.getValue());
		assertArrayEquals(new byte[] { (byte) expectedValue }, version.getValueAsI2osp1Byte());
	}
}

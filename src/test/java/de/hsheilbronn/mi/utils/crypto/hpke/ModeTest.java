package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ModeTest
{
	private static final byte[] PSK_ID = Sha256.digest("Test PSK Identifier".getBytes(StandardCharsets.US_ASCII));

	@Test
	void testPskFactoryMethods() throws Exception
	{
		assertDoesNotThrow(() -> Mode.base());
		assertDoesNotThrow(() -> Mode.psk(PSK_ID));
		assertThrowsExactly(NullPointerException.class, () -> Mode.psk(null));

		IllegalArgumentException e = assertThrowsExactly(IllegalArgumentException.class, () -> Mode.psk(new byte[0]));
		assertEquals("pskId.length <= 0", e.getMessage());
	}

	@Test
	@SuppressWarnings("unlikely-arg-type") // equals string
	void testBase() throws Exception
	{
		Mode base = Mode.base();
		assertArrayEquals(new byte[] { (byte) 0x00 }, base.getValueAsI2osp1Byte());
		assertArrayEquals(new byte[0], base.getPskId());

		assertFalse(base.isPsk());

		assertEquals(base.hashCode(), Mode.base().hashCode());
		assertTrue(base.equals(base));
		assertTrue(base.equals(Mode.base()));
		assertFalse(base.equals(Mode.psk(PSK_ID)));

		assertFalse(base.equals(null));
		assertFalse(base.equals(""));
	}

	@Test
	@SuppressWarnings("unlikely-arg-type") // equals string
	void testPsk() throws Exception
	{
		Mode psk = Mode.psk(PSK_ID);
		assertArrayEquals(new byte[] { (byte) 0x01 }, psk.getValueAsI2osp1Byte());
		assertArrayEquals(PSK_ID, psk.getPskId());

		assertTrue(psk.isPsk());

		assertEquals(psk.hashCode(), Mode.psk(PSK_ID).hashCode());
		assertTrue(psk.equals(psk));
		assertTrue(psk.equals(Mode.psk(PSK_ID)));
		assertFalse(psk.equals(Mode.psk(new byte[1])));
		assertFalse(psk.equals(Mode.base()));

		assertFalse(psk.equals(null));
		assertFalse(psk.equals(""));
	}

	private static Stream<Arguments> forTestFrom()
	{
		return Stream.of(Arguments.of(Mode.base(), 0x00, null), Arguments.of(Mode.psk(PSK_ID), 0x01, PSK_ID));
	}

	@ParameterizedTest
	@MethodSource("forTestFrom")
	void testFrom(Mode expected, int id, byte[] pskId) throws Exception
	{
		assertEquals(expected, Mode.from((byte) id, pskId));
	}

	private static Stream<Arguments> forTestFromInvalid()
	{
		return Stream.of(Arguments.of(0xFF, PSK_ID, IllegalArgumentException.class, "Mode not supported"),
				Arguments.of(Mode.PSK_VALUE, null, NullPointerException.class, "pskId"),
				Arguments.of(Mode.PSK_VALUE, new byte[0], IllegalArgumentException.class, "pskId.length <= 0"));
	}

	@ParameterizedTest
	@MethodSource("forTestFromInvalid")
	void testFromInvalid(int invalid, byte[] pskId, Class<? extends Exception> exceptionClass, String exceptionMessage)
			throws Exception
	{
		Exception exception = assertThrowsExactly(exceptionClass, () -> Mode.from((byte) invalid, pskId));
		assertEquals(exceptionMessage, exception.getMessage());
	}
}

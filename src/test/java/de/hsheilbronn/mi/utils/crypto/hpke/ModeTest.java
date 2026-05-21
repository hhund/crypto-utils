package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.HKDFParameterSpec.Builder;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ModeTest
{
	private static final byte[] PSK_ID = Sha256.digest("Test PSK Identifier".getBytes(StandardCharsets.US_ASCII));
	private static final SecretKey PSK = new SecretKeySpec(new byte[] { 'T', 'e', 's', 't', ' ', 'P', 'S', 'K' },
			"Generic");
	private static final PreSharedKeyProvider PSK_PROVIDER = PreSharedKeyProvider.of(PSK_ID, PSK);

	@Test
	void testPskFactoryMethods() throws Exception
	{
		assertDoesNotThrow(() -> Mode.base());
		assertDoesNotThrow(() -> Mode.psk(PSK_ID, PSK));
		assertDoesNotThrow(() -> Mode.psk(PSK_ID, _ -> PSK));
		assertThrowsExactly(NullPointerException.class, () -> Mode.psk(null, PSK));
		assertThrowsExactly(NullPointerException.class, () -> Mode.psk(null, _ -> PSK));
		assertThrowsExactly(NullPointerException.class, () -> Mode.psk(PSK_ID, (SecretKey) null));
		assertThrowsExactly(NullPointerException.class, () -> Mode.psk(PSK_ID, (PreSharedKeyProvider) null));

		IllegalArgumentException e = assertThrowsExactly(IllegalArgumentException.class,
				() -> Mode.psk(new byte[0], PSK));
		assertEquals("pskId.length <= 0", e.getMessage());

		e = assertThrowsExactly(IllegalArgumentException.class, () -> Mode.psk(new byte[0], _ -> PSK));
		assertEquals("pskId.length <= 0", e.getMessage());
	}

	@Test
	@SuppressWarnings("unlikely-arg-type") // equals string
	void testBase() throws Exception
	{
		Mode base = Mode.base();
		assertArrayEquals(new byte[] { (byte) 0x00 }, base.getValueAsI2osp1Byte());
		assertArrayEquals(new byte[0], base.getPskId());

		Builder builder = HKDFParameterSpec.ofExtract();
		assertEquals(0, builder.extractOnly().ikms().size());
		base.withPsk(builder);
		assertEquals(0, builder.extractOnly().ikms().size());

		assertFalse(base.isPsk());

		assertEquals(base.hashCode(), Mode.base().hashCode());
		assertTrue(base.equals(base));
		assertTrue(base.equals(Mode.base()));
		assertFalse(base.equals(Mode.psk(PSK_ID, PSK)));

		assertFalse(base.equals(null));
		assertFalse(base.equals(""));
	}

	@Test
	@SuppressWarnings("unlikely-arg-type") // equals string
	void testPsk() throws Exception
	{
		Mode psk = Mode.psk(PSK_ID, PSK);
		assertArrayEquals(new byte[] { (byte) 0x01 }, psk.getValueAsI2osp1Byte());
		assertArrayEquals(PSK_ID, psk.getPskId());

		Builder builder = HKDFParameterSpec.ofExtract();
		assertEquals(0, builder.extractOnly().ikms().size());
		psk.withPsk(builder);
		assertEquals(1, builder.extractOnly().ikms().size());
		assertArrayEquals(PSK.getEncoded(), builder.extractOnly().ikms().get(0).getEncoded());

		assertTrue(psk.isPsk());

		assertEquals(psk.hashCode(), Mode.psk(PSK_ID, PSK).hashCode());
		assertTrue(psk.equals(psk));
		assertTrue(psk.equals(Mode.psk(PSK_ID, PSK)));
		assertFalse(psk.equals(Mode.psk(new byte[1], PSK)));
		assertFalse(psk.equals(Mode.base()));

		assertFalse(psk.equals(null));
		assertFalse(psk.equals(""));
	}

	private static Stream<Arguments> forTestFrom()
	{
		return Stream.of(Arguments.of(Mode.base(), 0x00, null, (PreSharedKeyProvider) _ -> null),
				Arguments.of(Mode.psk(PSK_ID, PSK), 0x01, PSK_ID, PSK_PROVIDER));
	}

	@ParameterizedTest
	@MethodSource("forTestFrom")
	void testFrom(Mode expected, int id, byte[] pskId, PreSharedKeyProvider pskProvider) throws Exception
	{
		assertEquals(expected, Mode.from((byte) id, pskId, pskProvider));
	}

	private static Stream<Arguments> forTestFromInvalid()
	{
		return Stream.of(Arguments.of(0xFF, PSK_ID, PSK_PROVIDER, IllegalArgumentException.class, "Mode not supported"),
				Arguments.of(Mode.PSK_VALUE, PSK_ID, PreSharedKeyProvider.of(), KeyNotFoundException.class,
						KeyProvider.notFound("PSK", PSK_ID).getMessage()),
				Arguments.of(Mode.PSK_VALUE, null, PSK_PROVIDER, NullPointerException.class, "pskId"),
				Arguments.of(Mode.PSK_VALUE, new byte[0], PSK_PROVIDER, IllegalArgumentException.class,
						"pskId.length <= " + Header.PSK_ID_LENGTH));
	}

	@ParameterizedTest
	@MethodSource("forTestFromInvalid")
	void testFromInvalid(int invalid, byte[] pskId, PreSharedKeyProvider pskProvider,
			Class<? extends Exception> exceptionClass, String exceptionMessage) throws Exception
	{
		Exception exception = assertThrowsExactly(exceptionClass, () -> Mode.from((byte) invalid, pskId, pskProvider));
		assertEquals(exceptionMessage, exception.getMessage());
	}
}

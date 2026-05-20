package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HeaderTest
{
	private static final Logger logger = LoggerFactory.getLogger(HeaderTest.class);

	private static final byte[] PSK_ID = Sha256.digest("Test PSK Identifier".getBytes(StandardCharsets.US_ASCII));
	private static final SecretKey PSK = new SecretKeySpec(new byte[] { 'T', 'e', 's', 't', ' ', 'P', 'S', 'K' },
			"Generic");

	private static final byte[] RECEIVER_KEY_IDENTIFIER = Sha256
			.digest("Test Receiver Key Identifier".getBytes(StandardCharsets.US_ASCII));

	private static final Header HEADER_BASE = new Header(Version.V1, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256,
			KdfId.HKDF_SHA256, AeadId.AES_128_GCM, ChunkLength.KiB_1, RECEIVER_KEY_IDENTIFIER);
	private static final byte[] HEADER_BASE_BYTE_ARRAY = concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(),
			Mode.base().getValueAsI2osp1Byte(), KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
			KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
			ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER);

	private static final Header HEADER_PSK = new Header(Version.V1, Mode.psk(PSK_ID, PSK), KemId.DHKEM_P521_HKDF_SHA512,
			KdfId.HKDF_SHA512, AeadId.ChaCha20Poly1305, ChunkLength.MiB_1, RECEIVER_KEY_IDENTIFIER);
	private static final byte[] HEADER_PSK_BYTE_ARRAY = concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(),
			Mode.psk(PSK_ID, PSK).getValueAsI2osp1Byte(), KemId.DHKEM_P521_HKDF_SHA512.getIdAsI2osp2Bytes(),
			KdfId.HKDF_SHA512.getIdAsI2osp2Bytes(), AeadId.ChaCha20Poly1305.getIdAsI2osp2Bytes(),
			ChunkLength.MiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER, PSK_ID);

	private static final PskProvider pskProvider = pskId ->
	{
		if (Arrays.equals(PSK_ID, pskId))
			return PSK;
		else
			throw new KeyNotFoundException();
	};

	private static Stream<Arguments> forTestConstructorExceptions()
	{
		return Stream.of(
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256,
								KdfId.HKDF_SHA256, AeadId.AES_128_GCM, ChunkLength.KiB_1, RECEIVER_KEY_IDENTIFIER),
						null, null),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.psk(PSK_ID, PSK), KemId.DHKEM_P521_HKDF_SHA512,
								KdfId.HKDF_SHA512, AeadId.ChaCha20Poly1305, ChunkLength.KiB_1, RECEIVER_KEY_IDENTIFIER),
						null, null),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.psk(new byte[1], PSK),
								KemId.DHKEM_P521_HKDF_SHA512, KdfId.HKDF_SHA512, AeadId.ChaCha20Poly1305,
								ChunkLength.KiB_1, RECEIVER_KEY_IDENTIFIER),
						IllegalArgumentException.class, "mode.pskId.length != " + Header.PSK_ID_LENGTH),
				Arguments.of(
						(Executable) () -> new Header(null, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256,
								KdfId.HKDF_SHA256, AeadId.AES_128_GCM, ChunkLength.KiB_1, RECEIVER_KEY_IDENTIFIER),
						NullPointerException.class, "version"),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, null, KemId.DHKEM_X25519_HKDF_SHA256,
								KdfId.HKDF_SHA256, AeadId.AES_128_GCM, ChunkLength.KiB_1, RECEIVER_KEY_IDENTIFIER),
						NullPointerException.class, "mode"),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.base(), null, KdfId.HKDF_SHA256,
								AeadId.AES_128_GCM, ChunkLength.KiB_1, RECEIVER_KEY_IDENTIFIER),
						NullPointerException.class, "kemId"),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256, null,
								AeadId.AES_128_GCM, ChunkLength.KiB_1, RECEIVER_KEY_IDENTIFIER),
						NullPointerException.class, "kdfId"),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256,
								KdfId.HKDF_SHA256, null, ChunkLength.KiB_1, RECEIVER_KEY_IDENTIFIER),
						NullPointerException.class, "aeadId"),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256,
								KdfId.HKDF_SHA256, AeadId.AES_128_GCM, null, RECEIVER_KEY_IDENTIFIER),
						NullPointerException.class, "chunkLength"),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256,
								KdfId.HKDF_SHA256, AeadId.AES_128_GCM, ChunkLength.KiB_1, null),
						NullPointerException.class, "receiverKeyId"),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256,
								KdfId.HKDF_SHA256, AeadId.AES_128_GCM, ChunkLength.KiB_1, new byte[0]),
						IllegalArgumentException.class, "receiverKeyId.length != " + Header.RECEIVER_KEY_ID_LENGTH),
				Arguments.of(
						(Executable) () -> new Header(Version.V1, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256,
								KdfId.HKDF_SHA256, AeadId.AES_128_GCM, ChunkLength.KiB_1,
								new byte[Header.RECEIVER_KEY_ID_LENGTH + 1]),
						IllegalArgumentException.class, "receiverKeyId.length != " + Header.RECEIVER_KEY_ID_LENGTH));
	}

	@ParameterizedTest
	@MethodSource("forTestConstructorExceptions")
	void testConstructorExceptions(Executable executable, Class<? extends Exception> expectedExcpetion,
			String expectedMessage) throws Exception
	{
		if (expectedExcpetion == null)
			assertDoesNotThrow(executable);
		else
		{
			Exception e = assertThrowsExactly(expectedExcpetion, executable);
			assertEquals(expectedMessage, e.getMessage());
		}
	}

	private static Stream<Arguments> forTestWriteReadHeader()
	{
		return Stream.of(Arguments.of(HEADER_BASE, HEADER_BASE_BYTE_ARRAY, 1 * 1024),
				Arguments.of(HEADER_PSK, HEADER_PSK_BYTE_ARRAY, 1024 * 1024));
	}

	private static byte[] concat(byte[]... bytes)
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		Arrays.stream(bytes).forEach(out::writeBytes);
		return out.toByteArray();
	}

	@ParameterizedTest
	@MethodSource("forTestWriteReadHeader")
	void testWriteReadHeaderArray(Header header, byte[] expected, int chunkSize) throws Exception
	{
		assertEquals(chunkSize, header.getChunkLength());

		byte[] actual = header.getCanonical();

		logger.debug("Actual:   {}", HexFormat.of().formatHex(actual));
		logger.debug("Expected: {}", HexFormat.of().formatHex(expected));

		assertArrayEquals(expected, actual);

		Header readHeader = Header.from(expected, pskProvider);

		assertEquals(header.getAeadId(), readHeader.getAeadId());
		assertEquals(header.getChunkLength(), readHeader.getChunkLength());
		assertEquals(header.getKdfId(), readHeader.getKdfId());
		assertEquals(header.getKemId(), readHeader.getKemId());
		assertEquals(header.getMode(), readHeader.getMode());
		assertEquals(header.getVersion(), readHeader.getVersion());
		assertArrayEquals(header.getReceiverKeyId(), readHeader.getReceiverKeyId());
	}

	@ParameterizedTest
	@MethodSource("forTestWriteReadHeader")
	void testWriteReadHeaderStream(Header header, byte[] expected, int chunkSize) throws Exception
	{
		assertEquals(chunkSize, header.getChunkLength());

		byte[] actual = header.getCanonical();

		logger.debug("Actual:   {}", HexFormat.of().formatHex(actual));
		logger.debug("Expected: {}", HexFormat.of().formatHex(expected));

		assertArrayEquals(expected, actual);

		Header readHeader = Header.from(new ByteArrayInputStream(expected), pskProvider);

		assertEquals(header.getAeadId(), readHeader.getAeadId());
		assertEquals(header.getChunkLength(), readHeader.getChunkLength());
		assertEquals(header.getKdfId(), readHeader.getKdfId());
		assertEquals(header.getKemId(), readHeader.getKemId());
		assertEquals(header.getMode(), readHeader.getMode());
		assertEquals(header.getVersion(), readHeader.getVersion());
		assertArrayEquals(header.getReceiverKeyId(), readHeader.getReceiverKeyId());
	}

	private static Stream<Arguments> forTestReadInvalidHeadersFromByteArray()
	{
		return Stream.of(
				Arguments.of(concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(), Mode.base().getValueAsI2osp1Byte(),
						KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(), KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(),
						AeadId.AES_128_GCM.getIdAsI2osp2Bytes(), ChunkLength.KiB_1.getExponentAsI2osp1Byte()),
						"value.length < " + Header.HEADER_LENGHT),
				Arguments.of(
						concat("12345".getBytes(StandardCharsets.US_ASCII), Version.V1.getValueAsI2osp1Byte(),
								Mode.base().getValueAsI2osp1Byte(), KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
								KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
								ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER),
						"Magic value not supported"),
				Arguments.of(concat(Header.MAGIC, new byte[] { (byte) 0xFF }, Mode.base().getValueAsI2osp1Byte(),
						KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(), KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(),
						AeadId.AES_128_GCM.getIdAsI2osp2Bytes(), ChunkLength.KiB_1.getExponentAsI2osp1Byte(),
						RECEIVER_KEY_IDENTIFIER), "Version not supported"),
				Arguments.of(
						concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(), Mode.base().getValueAsI2osp1Byte(),
								KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
								KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
								ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER, new byte[1]),
						"Mode 0x00: value.length != " + Header.HEADER_LENGHT),
				Arguments.of(concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(),
						Mode.psk(PSK_ID, PSK).getValueAsI2osp1Byte(), KemId.DHKEM_P521_HKDF_SHA512.getIdAsI2osp2Bytes(),
						KdfId.HKDF_SHA512.getIdAsI2osp2Bytes(), AeadId.ChaCha20Poly1305.getIdAsI2osp2Bytes(),
						ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER, PSK_ID, new byte[1]),
						"Mode 0x01: value.length != " + (Header.HEADER_LENGHT + Header.PSK_ID_LENGTH)),
				Arguments.of(
						concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(), new byte[] { (byte) 0xFF },
								KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
								KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
								ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER),
						"Mode not supported"));
	}

	@ParameterizedTest
	@MethodSource("forTestReadInvalidHeadersFromByteArray")
	void testReadInvalidHeadersFromByteArray(byte[] invalid, String exceptionMessage) throws Exception
	{
		Exception exception = assertThrowsExactly(IllegalArgumentException.class,
				() -> Header.from(invalid, pskProvider));
		assertEquals(exceptionMessage, exception.getMessage());
	}

	private static Stream<Arguments> forTestReadInvalidHeadersFromStream()
	{
		return Stream.concat(
				Stream.of(
						Arguments.of(concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(),
								Mode.base().getValueAsI2osp1Byte(), KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
								KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
								ChunkLength.KiB_1.getExponentAsI2osp1Byte()), "Truncated stream"),
						Arguments.of(
								concat("12345".getBytes(StandardCharsets.US_ASCII), Version.V1.getValueAsI2osp1Byte(),
										Mode.base().getValueAsI2osp1Byte(),
										KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
										KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
										ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER),
								"Magic value not supported"),
						Arguments.of(concat(Header.MAGIC, new byte[] { (byte) 0xFF },
								Mode.base().getValueAsI2osp1Byte(), KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
								KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
								ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER),
								"Version not supported"),
						Arguments.of(concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(), new byte[] { (byte) 0xFF },
								KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
								KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
								ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER),
								"Mode not supported"),
						Arguments.of(
								concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(),
										Mode.base().getValueAsI2osp1Byte(),
										KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
										KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
										new byte[] { (byte) 0xFF }, RECEIVER_KEY_IDENTIFIER),
								"Chunk length exponent not supported"),
						Arguments.of(concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(),
								Mode.base().getValueAsI2osp1Byte(), KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
								KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
								new byte[] { (byte) 0x10 }, RECEIVER_KEY_IDENTIFIER),
								"Chunk length exponent not supported"),
						Arguments.of(
								concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(),
										Mode.base().getValueAsI2osp1Byte(), new byte[] { (byte) 0xFF, (byte) 0x00 },
										KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
										ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER),
								"KemId not supported"),
						Arguments.of(concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(),
								Mode.base().getValueAsI2osp1Byte(), KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
								new byte[] { (byte) 0xFF, (byte) 0xFF }, AeadId.AES_128_GCM.getIdAsI2osp2Bytes(),
								ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER),
								"KdfId not supported"),
						Arguments.of(concat(Header.MAGIC, Version.V1.getValueAsI2osp1Byte(),
								Mode.base().getValueAsI2osp1Byte(), KemId.DHKEM_X25519_HKDF_SHA256.getIdAsI2osp2Bytes(),
								KdfId.HKDF_SHA256.getIdAsI2osp2Bytes(), new byte[] { (byte) 0xFF, (byte) 0xFF },
								ChunkLength.KiB_1.getExponentAsI2osp1Byte(), RECEIVER_KEY_IDENTIFIER),
								"AeadId not supported")),
				Stream.concat(IntStream.range(1, HEADER_BASE_BYTE_ARRAY.length).mapToObj(trunc ->
				{
					byte[] truncated = new byte[HEADER_BASE_BYTE_ARRAY.length - trunc];
					ByteBuffer.wrap(HEADER_PSK_BYTE_ARRAY).get(truncated);
					return Arguments.argumentSet("Mode Base, truncated by " + trunc, truncated, "Truncated stream");
				}), IntStream.range(1, HEADER_PSK_BYTE_ARRAY.length).mapToObj(trunc ->
				{
					byte[] truncated = new byte[HEADER_PSK_BYTE_ARRAY.length - trunc];
					ByteBuffer.wrap(HEADER_PSK_BYTE_ARRAY).get(truncated);
					return Arguments.argumentSet("Mode PSK, truncated by " + trunc, truncated, "Truncated stream");
				})));
	}

	@ParameterizedTest
	@MethodSource("forTestReadInvalidHeadersFromStream")
	void testReadInvalidHeadersFromStream(byte[] invalid, String exceptionMessage) throws Exception
	{
		Exception exception = assertThrowsExactly(IOException.class,
				() -> Header.from(new ByteArrayInputStream(invalid), pskProvider));
		assertEquals(exceptionMessage, exception.getMessage());
	}

	private static Stream<Arguments> forTestGetChunkSize()
	{
		return Stream.of(Arguments.of(1 * 1024, ChunkLength.KiB_1), Arguments.of(2 * 1024, ChunkLength.KiB_2),
				Arguments.of(4 * 1024, ChunkLength.KiB_4), Arguments.of(8 * 1024, ChunkLength.KiB_8),
				Arguments.of(16 * 1024, ChunkLength.KiB_16), Arguments.of(32 * 1024, ChunkLength.KiB_32),
				Arguments.of(64 * 1024, ChunkLength.KiB_64), Arguments.of(128 * 1024, ChunkLength.KiB_128),
				Arguments.of(256 * 1024, ChunkLength.KiB_256), Arguments.of(512 * 1024, ChunkLength.KiB_512),
				Arguments.of(1 * 1024 * 1024, ChunkLength.MiB_1), Arguments.of(2 * 1024 * 1024, ChunkLength.MiB_2),
				Arguments.of(4 * 1024 * 1024, ChunkLength.MiB_4), Arguments.of(8 * 1024 * 1024, ChunkLength.MiB_8),
				Arguments.of(16 * 1024 * 1024, ChunkLength.MiB_16), Arguments.of(32 * 1024 * 1024, ChunkLength.MiB_32));
	}

	@ParameterizedTest
	@MethodSource("forTestGetChunkSize")
	void testGetChunkSize(int expectedChunkSize, ChunkLength chunkLength)
	{
		Header h = new Header(Version.V1, Mode.base(), KemId.DHKEM_X25519_HKDF_SHA256, KdfId.HKDF_SHA256,
				AeadId.AES_128_GCM, chunkLength, RECEIVER_KEY_IDENTIFIER);

		assertEquals(expectedChunkSize, h.getChunkLength());
	}
}

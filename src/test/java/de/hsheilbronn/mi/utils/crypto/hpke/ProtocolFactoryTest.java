package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.hpke.ProtocolFactory.ProtocolSerializer;

public class ProtocolFactoryTest
{
	private static final class TestProtocol implements Protocol
	{
		@Override
		public Mode getMode()
		{
			return null;
		}

		@Override
		public KemId getKemId()
		{
			return null;
		}

		@Override
		public KdfId getKdfId()
		{
			return null;
		}

		@Override
		public AeadId getAeadId()
		{
			return null;
		}

		@Override
		public int getChunkLength()
		{
			return 0;
		}

		@Override
		public byte[] getKdfInfo()
		{
			return null;
		}

		@Override
		public byte[] getReceiverKeyId()
		{
			return null;
		}
	}

	private static final ProtocolSerializer<TestProtocol> TEST_SERIALIZER = new ProtocolSerializer<ProtocolFactoryTest.TestProtocol>()
	{
		@Override
		public int getVersion()
		{
			return 0xFF;
		}

		@Override
		public TestProtocol read(InputStream stream, PreSharedKeyProvider preSharedKeyProvider,
				ReceiverPrivateKeyProvider receiverPrivateKeyProvider) throws IOException
		{
			return new TestProtocol();
		}

		@Override
		public Class<TestProtocol> getType()
		{
			return TestProtocol.class;
		}

		@Override
		public byte[] write(TestProtocol protocol)
		{
			return new byte[0];
		}
	};

	private static Stream<Arguments> forTestConstructor()
	{
		return Stream.of(
				Arguments.of((Supplier<ProtocolFactory>) () -> new ProtocolFactory(PreSharedKeyProvider.of(),
						ReceiverPrivateKeyProvider.of()), null, null),
				Arguments.of((Supplier<ProtocolFactory>) () -> new ProtocolFactory(PreSharedKeyProvider.of(),
						ReceiverPrivateKeyProvider.of(), null), null, null),
				Arguments.of((Supplier<ProtocolFactory>) () -> new ProtocolFactory(PreSharedKeyProvider.of(),
						ReceiverPrivateKeyProvider.of(), List.of()), null, null),
				Arguments.of((Supplier<ProtocolFactory>) () -> new ProtocolFactory(PreSharedKeyProvider.of(),
						ReceiverPrivateKeyProvider.of(), List.of(TEST_SERIALIZER)), null, null),
				Arguments.of((Supplier<ProtocolFactory>) () -> new ProtocolFactory(null,
						ReceiverPrivateKeyProvider.of(), List.of()), NullPointerException.class,
						"preSharedKeyProvider"),
				Arguments.of((Supplier<ProtocolFactory>) () -> new ProtocolFactory(PreSharedKeyProvider.of(), null,
						List.of()), NullPointerException.class, "receiverPrivateKeyProvider"),
				Arguments.of(
						(Supplier<ProtocolFactory>) () -> new ProtocolFactory(PreSharedKeyProvider.of(),
								ReceiverPrivateKeyProvider.of(), List.of(TEST_SERIALIZER, TEST_SERIALIZER)),
						IllegalArgumentException.class, "Multiple protocol serializers for same version"));
	}

	@MethodSource("forTestConstructor")
	@ParameterizedTest
	void testConstructor(Supplier<ProtocolFactory> constructor, Class<? extends Exception> expectedException,
			String expectedExceptionMessage) throws Exception
	{
		if (expectedException == null)
			assertDoesNotThrow(() -> constructor.get());
		else
		{
			Exception e = assertThrowsExactly(expectedException, () -> constructor.get());
			assertEquals(expectedExceptionMessage, e.getMessage());
		}
	}

	@Test
	void testWriteReadTestProtocol() throws Exception
	{
		ProtocolFactory factory = new ProtocolFactory(PreSharedKeyProvider.of(), ReceiverPrivateKeyProvider.of(),
				List.of(TEST_SERIALIZER))
		{
		};

		InputStream stream = factory.write(new TestProtocol());
		assertNotNull(stream);

		byte[] header = stream.readAllBytes();

		assertEquals(ProtocolFactory.ROOT_HEADER_LENGTH, header.length);
		assertArrayEquals(ByteEncoding.concat(ProtocolFactory.MAGIC, new byte[] { (byte) 0xFF }), header);

		Protocol read = factory.read(new ByteArrayInputStream(header));
		assertNotNull(read);
		assertTrue(read instanceof TestProtocol);
	}

	@Test
	void testWriteReadV1Protocol() throws Exception
	{
		ProtocolFactory factory = new ProtocolFactory(PreSharedKeyProvider.of(), ReceiverPrivateKeyProvider.of());

		InputStream stream = factory.write(new ProtocolV1(Mode.base(), KemId.DHKEM_P256_HKDF_SHA256, KdfId.HKDF_SHA256,
				AeadId.AES_128_GCM, ChunkLength.KiB_1, new byte[ProtocolV1.RECEIVER_KEY_ID_LENGTH]));
		assertNotNull(stream);

		byte[] header = stream.readAllBytes();

		assertEquals(ProtocolFactory.ROOT_HEADER_LENGTH + ProtocolV1.HEADER_BASE_LENGTH, header.length);

		Protocol read = factory.read(new ByteArrayInputStream(header));
		assertNotNull(read);
		assertTrue(read instanceof ProtocolV1);
	}

	@Test
	void testWriteReadTestAndV1Protocol() throws Exception
	{
		ProtocolFactory factory = new ProtocolFactory(PreSharedKeyProvider.of(), ReceiverPrivateKeyProvider.of(),
				List.of(TEST_SERIALIZER, ProtocolFactory.V1_SERIALIZER))
		{
		};

		InputStream streamV1 = factory.write(new ProtocolV1(Mode.base(), KemId.DHKEM_P256_HKDF_SHA256,
				KdfId.HKDF_SHA256, AeadId.AES_128_GCM, ChunkLength.KiB_1, new byte[ProtocolV1.RECEIVER_KEY_ID_LENGTH]));
		assertNotNull(streamV1);

		byte[] headerV1 = streamV1.readAllBytes();

		assertEquals(ProtocolFactory.ROOT_HEADER_LENGTH + ProtocolV1.HEADER_BASE_LENGTH, headerV1.length);

		Protocol readV1 = factory.read(new ByteArrayInputStream(headerV1));
		assertNotNull(readV1);
		assertTrue(readV1 instanceof ProtocolV1);

		InputStream streamTest = factory.write(new TestProtocol());
		assertNotNull(streamTest);

		byte[] headerTest = streamTest.readAllBytes();

		assertEquals(ProtocolFactory.ROOT_HEADER_LENGTH, headerTest.length);
		assertArrayEquals(ByteEncoding.concat(ProtocolFactory.MAGIC, new byte[] { (byte) 0xFF }), headerTest);

		Protocol readTest = factory.read(new ByteArrayInputStream(headerTest));
		assertNotNull(readTest);
		assertTrue(readTest instanceof TestProtocol);
	}

	@Test
	void testReadWriteNull() throws Exception
	{
		ProtocolFactory factory = new ProtocolFactory(PreSharedKeyProvider.of(), ReceiverPrivateKeyProvider.of());

		NullPointerException e = assertThrowsExactly(NullPointerException.class, () -> factory.write(null));
		assertEquals("protocol", e.getMessage());
		e = assertThrowsExactly(NullPointerException.class, () -> factory.read(null));
		assertEquals("source", e.getMessage());
	}

	@Test
	void testProtocolNotSupported() throws Exception
	{
		ProtocolFactory factory = new ProtocolFactory(PreSharedKeyProvider.of(), ReceiverPrivateKeyProvider.of());

		IllegalArgumentException iaE = assertThrowsExactly(IllegalArgumentException.class,
				() -> factory.write(new TestProtocol()));
		assertEquals("Protocol not supported", iaE.getMessage());

		IOException ioE = assertThrowsExactly(IOException.class, () -> factory.read(new ByteArrayInputStream(
				ByteEncoding.concat(ProtocolFactory.MAGIC, new byte[] { (byte) TEST_SERIALIZER.getVersion() }))));
		assertEquals("Protocol not supported", ioE.getMessage());
		ioE = assertThrowsExactly(IOException.class, () -> factory.read(new ByteArrayInputStream(ByteEncoding
				.concat(new byte[ProtocolFactory.MAGIC.length], new byte[] { (byte) TEST_SERIALIZER.getVersion() }))));
		assertEquals("Protocol not supported", ioE.getMessage());
	}
}

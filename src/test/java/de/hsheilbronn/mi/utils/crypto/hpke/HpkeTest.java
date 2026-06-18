package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.AEADBadTagException;
import javax.crypto.DecapsulateException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.hsheilbronn.mi.utils.crypto.hpke.ProtocolFactory.ProtocolSerializer;

public class HpkeTest
{
	private static final Logger logger = LoggerFactory.getLogger(HpkeTest.class);

	private static final long TWO_KIB = 2L * 1024;

	private static final byte[] PSK_ID = Sha256.digest("Test Pre Shared Key ID".getBytes(StandardCharsets.US_ASCII));
	private static final SecretKey PSK = new SecretKeySpec(new byte[] { 'T', 'e', 's', 't', ' ', 'P', 'S', 'K' },
			"Generic");
	private static final PreSharedKeyProvider PRE_SHARED_KEY_PROVIDER = PreSharedKeyProvider.of(PSK_ID, PSK);

	private static final byte[] RECEIVER_KEY_ID = Sha256
			.digest("Test Receiver Key ID".getBytes(StandardCharsets.US_ASCII));

	private static record ProtocolAndKeyPair(Protocol protocol, KeyPair keyPair)
	{
		@Override
		public final String toString()
		{
			return Stream
					.of("Mode " + protocol.getMode(), protocol.getKemId().name(), protocol.getKdfId().name(),
							protocol.getAeadId().name(), protocol.getChunkLength().name())
					.collect(Collectors.joining(", "));
		}

		Arguments toArguments(String plainText)
		{
			return Arguments.argumentSet(toString() + ", plainText: \"" + plainText + "\"", this, plainText);
		}

		Arguments toArguments()
		{
			return Arguments.argumentSet(toString(), this);
		}
	}

	private static Stream<Arguments> forTestEncryptDecryptInputStream() throws KeyNotFoundException
	{
		List<Mode> modes = List.of(Mode.base(), Mode.psk(PSK_ID));
		KemId[] kemIds = KemId.values();
		KdfId[] kdfIds = KdfId.values();
		AeadId[] aeadIds = AeadId.values();
		ChunkLength[] chunkLengths = ChunkLength.values();

		String plainText0 = "";
		String plainText1 = "Foo Bar Baz";

		return modes.stream().flatMap(mode ->
		{
			return Stream.of(kemIds).flatMap(kemId ->
			{
				KeyPair keyPair = kemId.getKeyPairGeneratorFactory().initialize().generateKeyPair();

				return Stream.of(kdfIds).flatMap(kdfId ->
				{
					return Stream.of(aeadIds).flatMap(aeadId ->
					{
						return Stream.of(chunkLengths).flatMap(chunklength ->
						{
							return Stream.of(plainText0, plainText1).map(plainText ->
							{
								return new ProtocolAndKeyPair(
										new ProtocolV1(mode, kemId, kdfId, aeadId, chunklength, RECEIVER_KEY_ID),
										keyPair).toArguments(plainText);
							});
						});
					});
				});
			});
		});
	}

	@ParameterizedTest
	@MethodSource("forTestEncryptDecryptInputStream")
	void testEncryptDecryptInputStream(ProtocolAndKeyPair protocolAndKeyPair, String plainText) throws Exception
	{
		final Hpke hpke = new Hpke(new ProtocolFactory(PRE_SHARED_KEY_PROVIDER,
				ReceiverPrivateKeyProvider.of(RECEIVER_KEY_ID, protocolAndKeyPair.keyPair().getPrivate())));

		byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] encrypted = hpke.encrypt(protocolAndKeyPair.protocol(), new ByteArrayInputStream(plainTextBytes),
				protocolAndKeyPair.keyPair().getPublic()).readAllBytes();

		logger.debug("{}, plaintText: \"{}\" - encrypted.length: {}", protocolAndKeyPair.toString(), plainText,
				encrypted.length);

		InputStream decryptedStream = hpke.decrypt(new ByteArrayInputStream(encrypted));
		assertNotNull(decryptedStream);

		byte[] decrypted = decryptedStream.readAllBytes();

		assertArrayEquals(plainTextBytes, decrypted);
	}

	private static Stream<Arguments> forDecryptionTruncatedStreamTest() throws KeyNotFoundException
	{
		BiConsumer<Integer, IOException> aesErrorHandler = (i, e) ->
		{
			if (i > 0 && i <= 1024 && e.getCause() instanceof AEADBadTagException badTag)
				assertEquals("Tag mismatch", badTag.getMessage());
			else if (i > 1024 && i <= 1024 + 15 && e.getCause() instanceof AEADBadTagException badTag)
				assertEquals("Input data too short to contain an expected tag length of 16bytes", badTag.getMessage());
			else if (i > 1024 + 15 && i <= 2048 + 16 && e.getCause() instanceof AEADBadTagException badTag)
				assertEquals("Tag mismatch", badTag.getMessage());
			else if (i > 2048 + 16 && i <= 2048 + 16 + 16 && e.getCause() instanceof AEADBadTagException badTag)
				assertEquals("Input data too short to contain an expected tag length of 16bytes", badTag.getMessage());
			else if (i > 2048 + 16 + 16)
				assertEquals("Truncated stream", e.getMessage());
			else
				fail("Truncated by " + i, e);
		};

		BiConsumer<Integer, IOException> chaCha20ErrorHandler = (i, e) ->
		{
			if (i > 0 && i <= 1024 && e.getCause() instanceof AEADBadTagException badTag)
				assertEquals("Tag mismatch", badTag.getMessage());
			else if (i > 1024 && i <= 1024 + 15 && e.getCause() instanceof AEADBadTagException badTag)
				assertEquals("Input too short - need tag", badTag.getMessage());
			else if (i > 1024 + 15 && i <= 2048 + 16 && e.getCause() instanceof AEADBadTagException badTag)
				assertEquals("Tag mismatch", badTag.getMessage());
			else if (i > 2048 + 16 && i <= 2048 + 16 + 16 && e.getCause() instanceof AEADBadTagException badTag)
				assertEquals("Input too short - need tag", badTag.getMessage());
			else if (i > 2048 + 16 + 16)
				assertEquals("Truncated stream", e.getMessage());
			else
				fail("Truncated by " + i, e);
		};

		return Stream.of(AeadId.values()).flatMap(aeadId -> Stream.of(KemId.values()).map(kemId ->
		{
			KeyPair keyPair = kemId.getKeyPairGeneratorFactory().initialize().generateKeyPair();
			ProtocolV1 header = new ProtocolV1(handleException(() -> Mode.psk(PSK_ID)), kemId, KdfId.HKDF_SHA256,
					aeadId, ChunkLength.KiB_1, RECEIVER_KEY_ID);
			ProtocolAndKeyPair hkp = new ProtocolAndKeyPair(header, keyPair);

			return Arguments.of(hkp, AeadId.ChaCha20Poly1305.equals(aeadId) ? chaCha20ErrorHandler : aesErrorHandler);
		}));
	}

	public interface SupplierWithException<T>
	{
		T get() throws Exception;
	}

	private static Mode handleException(SupplierWithException<Mode> modeSupplier)
	{
		try
		{
			return modeSupplier.get();
		}
		catch (Exception e)
		{
			throw new RuntimeException(e);
		}
	}

	@ParameterizedTest
	@MethodSource("forDecryptionTruncatedStreamTest")
	void decryptionTruncatedStreamTest(ProtocolAndKeyPair headerAndKeyPair,
			BiConsumer<Integer, IOException> errorHandler) throws Exception
	{
		final Hpke hpke = new Hpke(new ProtocolFactory(PRE_SHARED_KEY_PROVIDER,
				ReceiverPrivateKeyProvider.of(RECEIVER_KEY_ID, headerAndKeyPair.keyPair().getPrivate())));

		ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
		hpke.encrypt(headerAndKeyPair.protocol(), new ZeroInputStream(TWO_KIB), headerAndKeyPair.keyPair().getPublic(),
				encrypted);

		byte[] encryptedBytes = encrypted.toByteArray();
		assertNotNull(encryptedBytes);

		for (int i = 0; i <= encryptedBytes.length; i++)
		{
			try
			{
				hpke.decrypt(new ByteArrayInputStream(encryptedBytes, 0, encryptedBytes.length - i),
						OutputStream.nullOutputStream());

				assertEquals(0, i); // only not truncated stream ok
			}
			catch (IOException e)
			{
				errorHandler.accept(i, e);
			}
			catch (GeneralSecurityException e)
			{
				fail(e);
			}
		}
	}

	private static Stream<Arguments> forTestModifiedMessages() throws KeyNotFoundException
	{
		List<Mode> modes = List.of(Mode.base(), Mode.psk(PSK_ID));
		KemId[] kemIds = KemId.values();
		KdfId[] kdfIds = KdfId.values();
		AeadId[] aeadIds = AeadId.values();
		ChunkLength[] chunkLengths = ChunkLength.values();

		return modes.stream().flatMap(mode ->
		{
			return Stream.of(kemIds).flatMap(kemId ->
			{
				KeyPair keyPair = kemId.getKeyPairGeneratorFactory().initialize().generateKeyPair();

				return Stream.of(kdfIds).flatMap(kdfId ->
				{
					return Stream.of(aeadIds).flatMap(aeadId ->
					{
						return Stream.of(chunkLengths).map(chunkLength ->
						{
							return new ProtocolAndKeyPair(
									new ProtocolV1(mode, kemId, kdfId, aeadId, chunkLength, RECEIVER_KEY_ID), keyPair)
											.toArguments();
						});
					});
				});
			});
		});
	}

	private static final class TestProtocol extends ProtocolV1
	{
		public TestProtocol(Mode mode, KemId kemId, KdfId kdfId, AeadId aeadId, ChunkLength chunkLength,
				byte[] receiverKeyId)
		{
			super(mode, kemId, kdfId, aeadId, chunkLength, receiverKeyId);
		}

		public static TestProtocol from(InputStream source) throws IOException
		{
			ProtocolV1 v1 = ProtocolV1.from(source);
			return new TestProtocol(v1.getMode(), v1.getKemId(), v1.getKdfId(), v1.getAeadId(), v1.getChunkLength(),
					v1.getReceiverKeyId());
		}

		@Override
		public byte[] getKdfInfo()
		{
			byte[] kdfInfo = super.getKdfInfo();
			kdfInfo[kdfInfo.length - 2] = 0x02;
			return kdfInfo;
		}
	}

	private static final ProtocolSerializer<TestProtocol> TEST_SERIALIZER = new ProtocolSerializer<>()
	{
		@Override
		public int getVersion()
		{
			return 0x02;
		}

		@Override
		public TestProtocol read(InputStream source) throws IOException
		{
			return TestProtocol.from(source);
		}

		@Override
		public Class<TestProtocol> getType()
		{
			return TestProtocol.class;
		}

		@Override
		public byte[] write(TestProtocol protocol)
		{
			return protocol.getCanonicalHeader();
		}
	};

	@ParameterizedTest
	@MethodSource("forTestModifiedMessages")
	void testModifiedMessages(ProtocolAndKeyPair protocolAndKeyPair) throws Exception
	{
		ProtocolFactory protocolFactory = new ProtocolFactory(PRE_SHARED_KEY_PROVIDER,
				ReceiverPrivateKeyProvider.of(RECEIVER_KEY_ID, protocolAndKeyPair.keyPair().getPrivate()),
				List.of(ProtocolFactory.V1_SERIALIZER, TEST_SERIALIZER))
		{
		};
		Hpke hpke = new Hpke(protocolFactory);

		ZeroInputStream source = new ZeroInputStream(protocolAndKeyPair.protocol().getChunkLength().getLength() + 1);
		byte[] encrypted = hpke.encrypt(protocolAndKeyPair.protocol(), source, protocolAndKeyPair.keyPair().getPublic())
				.readAllBytes();

		logger.debug("{}", protocolAndKeyPair.toString());

		assertDoesNotThrow(() -> hpke.decrypt(new ByteArrayInputStream(encrypted), OutputStream.nullOutputStream()));

		AtomicInteger index = new AtomicInteger();

		// Magic
		byte[] m0 = encrypted.clone();
		m0[index.get()] = (byte) (m0[index.get()] ^ (byte) 0x01);
		expectException(hpke, m0, IOException.class);
		index.getAndUpdate(i -> i += 5);

		// Version
		byte[] m5Invalid = encrypted.clone();
		m5Invalid[index.get()] = (byte) 0xFF;
		expectException(hpke, m5Invalid, IOException.class);
		byte[] m5Version2 = encrypted.clone();
		m5Version2[index.get()] = (byte) 0x02;
		expectException(hpke, m5Version2, IOException.class);
		index.getAndUpdate(i -> i += 1);

		// Mode
		byte[] m6invalid = encrypted.clone();
		m6invalid[index.get()] = (byte) 0xFF;
		expectException(hpke, m6invalid, IOException.class);
		byte[] m6other = encrypted.clone();
		m6other[index
				.get()] = (byte) (protocolAndKeyPair.protocol().getMode().isPsk() ? Mode.BASE_VALUE : Mode.PSK_VALUE);
		expectException(hpke, m6other, IOException.class, KeyNotFoundException.class, DecapsulateException.class);
		index.getAndUpdate(i -> i += 1);

		// KemId
		byte[] m7invalid = encrypted.clone();
		m7invalid[index.get()] = (byte) 0xFE;
		m7invalid[index.get() + 1] = (byte) 0xFF;
		expectException(hpke, m7invalid, IOException.class);
		EnumSet.complementOf(EnumSet.of(protocolAndKeyPair.protocol().getKemId())).stream()
				.map(KemId::getIdAsI2osp2Bytes).forEach(other ->
				{
					byte[] m7other = encrypted.clone();
					m7other[index.get()] = other[0];
					m7other[index.get() + 1] = other[1];
					expectException(hpke, m7other, KeyNotSupportedException.class);
				});
		index.getAndUpdate(i -> i += 2);

		// KdfId
		byte[] m9invalid = encrypted.clone();
		m9invalid[index.get()] = (byte) 0xFF;
		m9invalid[index.get() + 1] = (byte) 0xFF;
		expectException(hpke, m9invalid, IOException.class);
		EnumSet.complementOf(EnumSet.of(protocolAndKeyPair.protocol().getKdfId())).stream()
				.map(KdfId::getIdAsI2osp2Bytes).forEach(other ->
				{
					byte[] m9other = encrypted.clone();
					m9other[index.get()] = other[0];
					m9other[index.get() + 1] = other[1];
					expectException(hpke, m9other, IOException.class);
				});
		index.getAndUpdate(i -> i += 2);

		// AeadId
		byte[] m11invalid = encrypted.clone();
		m11invalid[index.get()] = (byte) 0xFF;
		m11invalid[index.get() + 1] = (byte) 0xFF;
		expectException(hpke, m11invalid, IOException.class);
		EnumSet.complementOf(EnumSet.of(protocolAndKeyPair.protocol().getAeadId())).stream()
				.map(AeadId::getIdAsI2osp2Bytes).forEach(other ->
				{
					byte[] m11other = encrypted.clone();
					m11other[index.get()] = other[0];
					m11other[index.get() + 1] = other[1];
					expectException(hpke, m11other, IOException.class);
				});
		index.getAndUpdate(i -> i += 2);

		// Chunk length
		byte[] m13invalid = encrypted.clone();
		m13invalid[index.get()] = (byte) 0xFF;
		expectException(hpke, m13invalid, IOException.class);
		EnumSet.complementOf(EnumSet.of(protocolAndKeyPair.protocol().getChunkLength())).stream()
				.map(ChunkLength::getExponentAsI2osp1Byte).forEach(other ->
				{
					byte[] m11other = encrypted.clone();
					m11other[index.get()] = other[0];
					expectException(hpke, m11other, IOException.class);
				});
		index.getAndUpdate(i -> i += 1);

		// Receiver key ID
		byte[] m14 = encrypted.clone();
		m14[index.get()] = (byte) (m14[index.get()] ^ (byte) 0x01);
		expectException(hpke, m14, KeyNotFoundException.class);
		index.getAndUpdate(i -> i += ProtocolV1.RECEIVER_KEY_ID_LENGTH);

		// Pre shared key
		if (protocolAndKeyPair.protocol().getMode().isPsk())
		{
			byte[] m46 = encrypted.clone();
			m46[index.get()] = (byte) (m46[index.get()] ^ (byte) 0x01);
			expectException(hpke, m46, KeyNotFoundException.class);
			index.getAndUpdate(i -> i += ProtocolV1.PRE_SHARED_KEY_ID_LENGTH);
		}

		// Encapsulation
		byte[] mEnc = encrypted.clone();
		mEnc[index.get()] = (byte) (mEnc[index.get()] ^ (byte) 0x01);
		expectException(hpke, mEnc, IOException.class, DecapsulateException.class);
		index.getAndUpdate(i -> i += protocolAndKeyPair.protocol().getKemId().getEncapsulationLength());

		// First Chunk
		byte[] mC0 = encrypted.clone();
		mC0[index.get()] = (byte) (mC0[index.get()] ^ (byte) 0x01);
		expectException(hpke, mC0, IOException.class);

		// additional data at end
		byte[] all = encrypted.clone();
		expectException(hpke, ByteEncoding.concat(all, new byte[1]), IOException.class);
	}

	private void expectException(Hpke hpke, byte[] modified, Class<?>... expected)
	{
		try
		{
			hpke.decrypt(new ByteArrayInputStream(modified), OutputStream.nullOutputStream());
			fail("Exception expected");
		}
		catch (IOException | GeneralSecurityException | KeyNotFoundException | KeyNotSupportedException e)
		{
			if (!List.of(expected).contains(e.getClass()))
				fail("Exception of type " + e.getClass().getName() + " (message: " + e.getMessage() + ") not expected");
		}
	}
}

package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
import java.util.List;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HpkeTest
{
	private static final Logger logger = LoggerFactory.getLogger(HpkeTest.class);

	private static final long TWO_KIB = 2L * 1024;

	private static final byte[] PSK_ID = Sha256.digest("Test Pre Shared Key ID".getBytes(StandardCharsets.US_ASCII));
	private static final SecretKey PSK = new SecretKeySpec(new byte[] { 'T', 'e', 's', 't', ' ', 'P', 'S', 'K' },
			"Generic");
	private static final byte[] RECEIVER_KEY_ID = Sha256
			.digest("Test Receiver Key ID".getBytes(StandardCharsets.US_ASCII));
	private static final PreSharedKeyProvider PSK_PROVIDER = _ -> PSK;

	private static final Hpke hpke = new Hpke(PSK_PROVIDER);

	private static record HeaderAndKeyPair(Header header, KeyPair keyPair)
	{
		@Override
		public final String toString()
		{
			return Stream
					.of("Version " + header.getVersion(), "Mode " + header.getMode(), header.getKemId().name(),
							header.getKdfId().name(), header.getAeadId().name(), header.getChunkLength() + " KiB")
					.collect(Collectors.joining(", "));
		}

		Arguments toArguments(String plainText)
		{
			return Arguments.argumentSet(toString() + ", plainText: \"" + plainText + "\"", this, plainText);
		}
	}

	private static Stream<Arguments> forTestEncryptDecryptInputStream() throws KeyNotFoundException
	{
		List<Mode> modes = List.of(Mode.base(), Mode.psk(PSK_ID, PSK_PROVIDER));
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
								return new HeaderAndKeyPair(new Header(Version.V1, mode, kemId, kdfId, aeadId,
										chunklength, RECEIVER_KEY_ID), keyPair).toArguments(plainText);
							});
						});
					});
				});
			});
		});
	}

	@ParameterizedTest
	@MethodSource("forTestEncryptDecryptInputStream")
	void testEncryptDecryptInputStream(HeaderAndKeyPair headerAndKeyPair, String plainText) throws Exception
	{
		byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
		byte[] encrypted = hpke.encrypt(headerAndKeyPair.header(), new ByteArrayInputStream(plainTextBytes),
				headerAndKeyPair.keyPair().getPublic()).readAllBytes();

		logger.debug("{}, plaintText: \"{}\" - encrypted.length: {}", headerAndKeyPair.toString(), plainText,
				encrypted.length);

		InputStream decryptedStream = hpke.decrypt(new ByteArrayInputStream(encrypted),
				headerAndKeyPair.keyPair().getPrivate());
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

		return Stream.of(AeadId.values()).map(aeadId ->
		{
			Header header = new Header(Version.V1, handleException(() -> Mode.psk(PSK_ID, PSK_PROVIDER)),
					KemId.RSAKEM_1024_KDF2_SHA256, KdfId.HKDF_SHA256, aeadId, ChunkLength.KiB_1, RECEIVER_KEY_ID);
			KeyPair keyPair = header.getKemId().getKeyPairGeneratorFactory().initialize().generateKeyPair();
			HeaderAndKeyPair hkp = new HeaderAndKeyPair(header, keyPair);

			return Arguments.of(hkp, AeadId.ChaCha20Poly1305.equals(aeadId) ? chaCha20ErrorHandler : aesErrorHandler);
		});
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
	void decryptionTruncatedStreamTest(HeaderAndKeyPair headerAndKeyPair, BiConsumer<Integer, IOException> errorHandler)
			throws Exception
	{
		ByteArrayOutputStream encrypted = new ByteArrayOutputStream();

		hpke.encrypt(headerAndKeyPair.header(), new ZeroInputStream(TWO_KIB), headerAndKeyPair.keyPair().getPublic(),
				encrypted);

		byte[] encryptedBytes = encrypted.toByteArray();
		assertNotNull(encryptedBytes);

		for (int i = 0; i <= encryptedBytes.length; i++)
		{
			try
			{
				hpke.decrypt(new ByteArrayInputStream(encryptedBytes, 0, encryptedBytes.length - i),
						headerAndKeyPair.keyPair().getPrivate(), OutputStream.nullOutputStream());

				assertEquals(i, 0); // only not truncated stream ok
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
}

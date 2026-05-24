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
import java.io.SequenceInputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.hpke.ChunkedInputStreamEnumeration.CryptOperation;

public class ChunkedInputStreamEnumerationTest
{
	@Test
	void testConstructor() throws Exception
	{
		CryptOperation op = (_, _, _, _) -> null;
		byte[] baseNonce = new byte[1];
		InputStream source = InputStream.nullInputStream();

		assertDoesNotThrow(() -> new ChunkedInputStreamEnumeration(1, baseNonce, source, op));
		assertThrowsExactly(IllegalArgumentException.class,
				() -> new ChunkedInputStreamEnumeration(Integer.MIN_VALUE, baseNonce, source, op));
		assertThrowsExactly(IllegalArgumentException.class,
				() -> new ChunkedInputStreamEnumeration(-1, baseNonce, source, op));
		assertThrowsExactly(IllegalArgumentException.class,
				() -> new ChunkedInputStreamEnumeration(0, baseNonce, source, op));

		assertThrowsExactly(NullPointerException.class, () -> new ChunkedInputStreamEnumeration(1, null, source, op));
		assertThrowsExactly(IllegalArgumentException.class,
				() -> new ChunkedInputStreamEnumeration(1, new byte[0], source, op));
		assertThrowsExactly(NullPointerException.class,
				() -> new ChunkedInputStreamEnumeration(1, baseNonce, null, op));
		assertThrowsExactly(NullPointerException.class,
				() -> new ChunkedInputStreamEnumeration(1, baseNonce, source, null));
	}

	@Test
	void testChunking() throws Exception
	{
		CryptOperation op = (iv, sequence, finished, chunk) ->
		{
			assertNotNull(iv);
			assertEquals(2, iv.length);
			assertNotNull(sequence);
			assertEquals(2, sequence.length);
			assertNotNull(chunk);
			assertEquals(1, chunk.length);

			ByteBuffer b = ByteBuffer.allocate(2 + 2 + 1 + 1);

			b.put(iv);
			b.put(sequence);
			b.put(finished ? (byte) 0x01 : (byte) 0x00);
			b.put(chunk);

			return new ByteArrayInputStream(b.array());
		};
		byte[] baseNonce = new byte[] { (byte) 0xFF, (byte) 0x00 };
		InputStream source = new ByteArrayInputStream(new byte[] { (byte) 0xAA, (byte) 0xBB });

		ChunkedInputStreamEnumeration e = new ChunkedInputStreamEnumeration(1, baseNonce, source, op);
		ArrayList<InputStream> results = Collections.list(e);
		assertEquals(2, results.size());
		assertArrayEquals(HexFormat.of().parseHex("FF00000000AA"), results.get(0).readAllBytes());
		assertArrayEquals(HexFormat.of().parseHex("FF01000101BB"), results.get(1).readAllBytes());
	}

	@Test
	void testChunkingEmptyInput() throws Exception
	{
		CryptOperation op = (iv, sequence, finished, chunk) ->
		{
			assertNotNull(iv);
			assertEquals(2, iv.length);
			assertNotNull(sequence);
			assertEquals(2, sequence.length);
			assertNotNull(chunk);
			assertEquals(0, chunk.length);

			ByteBuffer b = ByteBuffer.allocate(2 + 2 + 1);

			b.put(iv);
			b.put(sequence);
			b.put(finished ? (byte) 0x01 : (byte) 0x00);

			return new ByteArrayInputStream(b.array());
		};
		byte[] baseNonce = new byte[] { (byte) 0xFF, (byte) 0x00 };
		InputStream source = InputStream.nullInputStream();

		ChunkedInputStreamEnumeration e = new ChunkedInputStreamEnumeration(1, baseNonce, source, op);
		ArrayList<InputStream> results = Collections.list(e);
		assertEquals(1, results.size());
		assertArrayEquals(HexFormat.of().parseHex("FF00000001"), results.get(0).readAllBytes());
	}

	@Test
	void testChunkingSourceShorterThenChunkLenght() throws Exception
	{
		CryptOperation op = (iv, sequence, finished, chunk) ->
		{
			assertNotNull(iv);
			assertEquals(2, iv.length);
			assertNotNull(sequence);
			assertEquals(2, sequence.length);
			assertNotNull(chunk);
			assertTrue(chunk.length > 0);

			ByteBuffer b = ByteBuffer.allocate(2 + 2 + 1 + chunk.length);

			b.put(iv);
			b.put(sequence);
			b.put(finished ? (byte) 0x01 : (byte) 0x00);
			b.put(chunk);

			return new ByteArrayInputStream(b.array());
		};
		byte[] baseNonce = new byte[] { (byte) 0xFF, (byte) 0x00 };
		InputStream source = new ByteArrayInputStream(new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC });

		ChunkedInputStreamEnumeration e = new ChunkedInputStreamEnumeration(2, baseNonce, source, op);
		ArrayList<InputStream> results = Collections.list(e);
		assertEquals(2, results.size());
		assertArrayEquals(HexFormat.of().parseHex("FF00000000AABB"), results.get(0).readAllBytes());
		assertArrayEquals(HexFormat.of().parseHex("FF01000101CC"), results.get(1).readAllBytes());
	}

	@Test
	void testChunkingSourceThrowsIOException() throws Exception
	{
		final int chunkLength = 2;
		final IOException readException = new IOException("simmulated failed read");
		final IOException closeException = new IOException("simmulated failed close");

		CryptOperation op = (_, _, _, _) -> InputStream.nullInputStream();
		byte[] baseNonce = new byte[] { (byte) 0xFF, (byte) 0x00 };
		InputStream source = new ByteArrayInputStream(new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC });

		InputStream sourceWrapper = new InputStream()
		{
			int counter = 0;

			@Override
			public int read(byte[] b, int off, int len) throws IOException
			{
				if (counter >= chunkLength)
					throw readException;

				int i = source.read(b, off, len);
				counter += i;
				return i;
			}

			@Override
			public int read() throws IOException
			{
				throw new IOException("Unexpected call of read() in test");
			}

			@Override
			public void close() throws IOException
			{
				throw closeException;
			}
		};

		ChunkedInputStreamEnumeration enumeration = new ChunkedInputStreamEnumeration(chunkLength, baseNonce,
				sourceWrapper, op);
		assertDoesNotThrow(() -> enumeration.hasMoreElements());
		assertDoesNotThrow(() -> enumeration.nextElement());
		assertDoesNotThrow(() -> enumeration.hasMoreElements());
		RuntimeIOException e = assertThrowsExactly(RuntimeIOException.class, () -> enumeration.nextElement());
		assertNotNull(e.getCause());
		assertEquals(readException, e.getCause());
		assertNotNull(e.getCause().getSuppressed());
		assertEquals(1, e.getCause().getSuppressed().length);
		assertEquals(closeException, e.getCause().getSuppressed()[0]);
	}

	private static final HexFormat HEX = HexFormat.of();

	private static record TestVector(AeadId aeadId, SecretKey key, byte[] baseNonce, Map<Integer, TestVectorData> data)
	{
		static TestVector of(AeadId aeadId, String keyHex, String baseNonceHex, Map<Integer, TestVectorData> data)
		{
			SecretKeySpec key = new SecretKeySpec(HEX.parseHex(keyHex), aeadId.getKeyAlgorithm());
			return new TestVector(aeadId, key, HEX.parseHex(baseNonceHex), data);
		}
	}

	private static record TestVectorData(byte[] aad, byte[] nonce, byte[] ct)
	{
		static TestVectorData of(String aadHex, String nonceHex, String ctHex)
		{
			return new TestVectorData(HEX.parseHex(aadHex), HEX.parseHex(nonceHex), HEX.parseHex(ctHex));
		}
	}

	// Test Data from https://www.rfc-editor.org/rfc/rfc9180.html#name-test-vectors

	private static final byte[] PT = HexFormat.of()
			.parseHex("4265617574792069732074727574682c20747275746820626561757479");

	private static final String aad0 = "436f756e742d30";
	private static final String aad1 = "436f756e742d31";
	private static final String aad2 = "436f756e742d32";
	private static final String aad4 = "436f756e742d34";
	private static final String aad255 = "436f756e742d323535";
	private static final String aad256 = "436f756e742d323536";

	// A.1.1.1. Encryptions
	private static final Map<Integer, TestVectorData> A1_DATA = Map.of(0,
			TestVectorData.of(aad0, "56d890e5accaaf011cff4b7d",
					"f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
			1,
			TestVectorData.of(aad1, "56d890e5accaaf011cff4b7c",
					"af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
			2,
			TestVectorData.of(aad2, "56d890e5accaaf011cff4b7f",
					"498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"),
			4,
			TestVectorData.of(aad4, "56d890e5accaaf011cff4b79",
					"583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d"),
			255,
			TestVectorData.of(aad255, "56d890e5accaaf011cff4b82",
					"7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a"),
			256, TestVectorData.of(aad256, "56d890e5accaaf011cff4a7d",
					"957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"));

	// A.2.1.1. Encryptions
	private static final Map<Integer, TestVectorData> A2_DATA = Map.of(0,
			TestVectorData.of(aad0, "5c4d98150661b848853b547f",
					"1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"),
			1,
			TestVectorData.of(aad1, "5c4d98150661b848853b547e",
					"6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"),
			2,
			TestVectorData.of(aad2, "5c4d98150661b848853b547d",
					"71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b"),
			4,
			TestVectorData.of(aad4, "5c4d98150661b848853b547b",
					"63357a2aa291f5a4e5f27db6baa2af8cf77427c7c1a909e0b37214dd47db122bb153495ff0b02e9e54a50dbe16"),
			255,
			TestVectorData.of(aad255, "5c4d98150661b848853b5480",
					"18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c"),
			256, TestVectorData.of(aad256, "5c4d98150661b848853b557f",
					"7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b"));

	// A.6.1.1. Encryptions
	private static final Map<Integer, TestVectorData> A6_DATA = Map.of(0,
			TestVectorData.of(aad0, "55ff7a7d739c69f44b25447b",
					"170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a"),
			1,
			TestVectorData.of(aad1, "55ff7a7d739c69f44b25447a",
					"d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256"),
			2,
			TestVectorData.of(aad2, "55ff7a7d739c69f44b254479",
					"142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b61d24e1c7a"),
			4,
			TestVectorData.of(aad4, "55ff7a7d739c69f44b25447f",
					"3bb3a5a07100e5a12805327bf3b152df728b1c1be75a9fd2cb2bf5eac0cca1fb80addb37eb2a32938c7268e3e5"),
			255,
			TestVectorData.of(aad255, "55ff7a7d739c69f44b254484",
					"4f268d0930f8d50b8fd9d0f26657ba25b5cb08b308c92e33382f369c768b558e113ac95a4c70dd60909ad1adc7"),
			256, TestVectorData.of(aad256, "55ff7a7d739c69f44b25457b",
					"dbbfc44ae037864e75f136e8b4b4123351d480e6619ae0e0ae437f036f2f8f1ef677686323977a1ccbb4b4f16a"));

	private static final TestVector A1 = TestVector.of(AeadId.AES_128_GCM, "4531685d41d65f03dc48f6b8302c05b0",
			"56d890e5accaaf011cff4b7d", A1_DATA);
	private static final TestVector A2 = TestVector.of(AeadId.ChaCha20Poly1305,
			"ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91", "5c4d98150661b848853b547f", A2_DATA);
	private static final TestVector A6 = TestVector.of(AeadId.AES_256_GCM,
			"751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70", "55ff7a7d739c69f44b25447b", A6_DATA);

	private static Stream<Arguments> forTestWithRfcTestVector() throws KeyNotFoundException
	{
		return Stream.of(A1, A2, A6).map(Arguments::of);
	}

	@ParameterizedTest
	@MethodSource("forTestWithRfcTestVector")
	void testWithRfcTestVector(TestVector vector) throws Exception
	{
		AeadId aeadId = vector.aeadId();
		AtomicInteger counter = new AtomicInteger();

		Cipher cipher = aeadId.toCipher();
		CryptOperation op = (iv, _, _, chunk) ->
		{
			int c = counter.getAndIncrement();

			Optional.ofNullable(vector.data().get(c)).map(TestVectorData::nonce)
					.ifPresent(n -> assertArrayEquals(n, iv));

			aeadId.initEncryptionCipher(cipher, vector.key(), iv);
			Optional.ofNullable(vector.data().get(c)).map(TestVectorData::aad).ifPresent(a -> cipher.updateAAD(a));

			return new ByteArrayInputStream(cipher.doFinal(chunk));
		};

		InputStream source = new SequenceInputStream(Collections
				.enumeration(IntStream.rangeClosed(0, 256).mapToObj(_ -> PT).map(ByteArrayInputStream::new).toList()));

		ChunkedInputStreamEnumeration e = new ChunkedInputStreamEnumeration(PT.length, vector.baseNonce(), source, op);
		List<byte[]> results = Collections.list(e).stream().map(readAllBytes()).toList();
		assertEquals(257, results.size());

		vector.data().forEach((i, data) -> assertArrayEquals(data.ct(), results.get(i)));
	}

	private Function<InputStream, byte[]> readAllBytes()
	{
		return in ->
		{
			try
			{
				return in.readAllBytes();
			}
			catch (IOException e)
			{
				throw new RuntimeException(e);
			}
		};
	}

	@Test
	void testSequenceLimit() throws Exception
	{
		ChunkedInputStreamEnumeration en = new ChunkedInputStreamEnumeration(1, new byte[1],
				new ByteArrayInputStream(new byte[0xFF + 1]), (_, _, _, _) -> null);

		RuntimeIOException e = assertThrowsExactly(RuntimeIOException.class, () -> Collections.list(en));
		assertEquals("Message limit reached", e.getMessage());
	}
}

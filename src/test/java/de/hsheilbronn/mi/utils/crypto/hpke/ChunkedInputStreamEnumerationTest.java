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
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

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

	@Test
	void testWithRfcTestVectorFromA11() throws Exception
	{
		AeadId aeadId = AeadId.AES_128_GCM;

		SecretKey key = new SecretKeySpec(HexFormat.of().parseHex("4531685d41d65f03dc48f6b8302c05b0"), "AES");
		byte[] baseNonce = HexFormat.of().parseHex("56d890e5accaaf011cff4b7d");
		byte[] pt = HexFormat.of().parseHex("4265617574792069732074727574682c20747275746820626561757479");

		byte[] aad0 = HexFormat.of().parseHex("436f756e742d30");
		byte[] nonce0 = HexFormat.of().parseHex("56d890e5accaaf011cff4b7d");
		byte[] ct0 = HexFormat.of()
				.parseHex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");

		byte[] aad1 = HexFormat.of().parseHex("436f756e742d31");
		byte[] nonce1 = HexFormat.of().parseHex("56d890e5accaaf011cff4b7c");
		byte[] ct1 = HexFormat.of()
				.parseHex("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84");

		byte[] aad2 = HexFormat.of().parseHex("436f756e742d32");
		byte[] nonce2 = HexFormat.of().parseHex("56d890e5accaaf011cff4b7f");
		byte[] ct2 = HexFormat.of()
				.parseHex("498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180");

		byte[] aad4 = HexFormat.of().parseHex("436f756e742d34");
		byte[] nonce4 = HexFormat.of().parseHex("56d890e5accaaf011cff4b79");
		byte[] ct4 = HexFormat.of()
				.parseHex("583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d");

		byte[] aad255 = HexFormat.of().parseHex("436f756e742d323535");
		byte[] nonce255 = HexFormat.of().parseHex("56d890e5accaaf011cff4b82");
		byte[] ct255 = HexFormat.of()
				.parseHex("7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a");

		byte[] aad256 = HexFormat.of().parseHex("436f756e742d323536");
		byte[] nonce256 = HexFormat.of().parseHex("56d890e5accaaf011cff4a7d");
		byte[] ct256 = HexFormat.of()
				.parseHex("957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2");

		Map<Integer, byte[]> aads = Map.of(0, aad0, 1, aad1, 2, aad2, 4, aad4, 255, aad255, 256, aad256);
		Map<Integer, byte[]> nonces = Map.of(0, nonce0, 1, nonce1, 2, nonce2, 4, nonce4, 255, nonce255, 256, nonce256);

		assertEquals(6, aads.size());
		assertEquals(6, nonces.size());

		AtomicInteger counter = new AtomicInteger();

		Cipher cipher = aeadId.toCipher();
		CryptOperation op = (iv, _, _, chunk) ->
		{
			int c = counter.getAndIncrement();

			byte[] n = nonces.get(c);
			if (n != null)
				assertArrayEquals(n, iv);

			aeadId.initEncryptionCipher(cipher, key, iv);

			byte[] aad = aads.getOrDefault(c, new byte[0]);
			cipher.updateAAD(aad);

			byte[] encrypted = cipher.doFinal(chunk);
			return new ByteArrayInputStream(encrypted);
		};
		InputStream source = new SequenceInputStream(Collections
				.enumeration(IntStream.rangeClosed(0, 256).mapToObj(_ -> pt).map(ByteArrayInputStream::new).toList()));

		ChunkedInputStreamEnumeration e = new ChunkedInputStreamEnumeration(pt.length, baseNonce, source, op);
		ArrayList<InputStream> results = Collections.list(e);
		assertEquals(257, results.size()); //

		assertArrayEquals(ct0, results.get(0).readAllBytes());
		assertArrayEquals(ct1, results.get(1).readAllBytes());
		assertArrayEquals(ct2, results.get(2).readAllBytes());
		assertArrayEquals(ct4, results.get(4).readAllBytes());
		assertArrayEquals(ct255, results.get(255).readAllBytes());
		assertArrayEquals(ct256, results.get(256).readAllBytes());
	}
}

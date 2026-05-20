package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Enumeration;
import java.util.NoSuchElementException;

public class ChunkedInputStreamEnumeration implements Enumeration<InputStream>
{
	@FunctionalInterface
	public interface CryptOperation
	{
		InputStream apply(byte[] iv, byte[] sequence, boolean finished, byte[] currentChunk)
				throws IOException, GeneralSecurityException;
	}

	private final int chunkSize;
	private final byte[] baseNonce;
	private final InputStream source;
	private final CryptOperation cryptOperation;

	private byte[] nextChunk;
	private boolean finished = false;

	private boolean first = true;
	private final byte[] sequence;

	ChunkedInputStreamEnumeration(int chunkSize, byte[] baseNonce, InputStream source, CryptOperation cryptOperation)
	{
		this.chunkSize = chunkSize;
		this.baseNonce = baseNonce;
		this.source = source;
		this.cryptOperation = cryptOperation;

		this.sequence = new byte[baseNonce.length];

		loadNextChunk();
	}

	@Override
	public boolean hasMoreElements()
	{
		return nextChunk != null || first;
	}

	@Override
	public InputStream nextElement()
	{
		if (nextChunk == null && !first)
			throw new NoSuchElementException();

		boolean finished = this.finished;
		byte[] currentChunk = this.nextChunk;
		byte[] currentSequence = this.sequence;

		if (currentChunk == null && first)
			currentChunk = new byte[0];

		loadNextChunk();
		incrementSequence();

		if (this.nextChunk == null)
			finished = true;

		try
		{
			return cryptOperation.apply(createNonce(), currentSequence, finished, currentChunk);
		}
		catch (IOException e)
		{
			throw new RuntimeIOException(e);
		}
		catch (GeneralSecurityException e)
		{
			throw new RuntimeIOException(new IOException(e));
		}
	}

	private void loadNextChunk()
	{
		if (finished)
		{
			nextChunk = null;
			return;
		}

		byte[] buffer = new byte[chunkSize];
		int offset = 0;

		try
		{
			while (offset < chunkSize)
			{
				int read = source.read(buffer, offset, chunkSize - offset);
				if (read == -1)
					break;

				offset += read;
			}

			if (offset == 0)
			{
				finished = true;
				nextChunk = null;

				source.close();
			}
			else if (offset < chunkSize)
			{
				byte[] lastChunk = new byte[offset];
				System.arraycopy(buffer, 0, lastChunk, 0, offset);
				nextChunk = lastChunk;
				finished = true;

				source.close();
			}
			else
				nextChunk = buffer;
		}
		catch (IOException e)
		{
			finished = true;
			nextChunk = null;

			try
			{
				source.close();
			}
			catch (IOException closeE)
			{
				e.addSuppressed(closeE);
			}

			throw new RuntimeIOException(e);
		}
	}

	private byte[] createNonce()
	{
		byte[] result = new byte[baseNonce.length];
		for (int i = 0; i < baseNonce.length; i++)
			result[i] = (byte) (baseNonce[i] ^ sequence[i]);
		return result;
	}

	private void incrementSequence()
	{
		if (first)
			first = false;

		for (int i = sequence.length - 1; i >= 0; i--)
			if (++sequence[i] != 0)
				return;

		throw new IllegalStateException("Message limit reached");
	}
}

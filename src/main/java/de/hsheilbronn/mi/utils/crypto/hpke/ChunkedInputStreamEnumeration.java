package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.util.Objects;

/**
 * This enumeration emits one final empty chunk for empty inputs so that the cryptographic operation can produce final
 * authentication output.<br>
 * <br>
 * Per chunk initialization vectors are calculated as "baseNonce XOR sequence". The sequence starts at 0 for the first
 * chunk is incremented by 1 for every chunk.<br>
 * <br>
 * {@link IOException}s throw by the source {@link InputStream} are re-thrown as {@link RuntimeIOException}s and can be
 * translated back to {@link IOException}s via {@link SequenceInputStreamForRuntimeIOException}.<br>
 * <br>
 * <b>The implementation is not thread-save.</b>
 * 
 * @see SequenceInputStreamForRuntimeIOException
 */
public class ChunkedInputStreamEnumeration implements Enumeration<InputStream>
{
	@FunctionalInterface
	public interface CryptOperation
	{
		InputStream apply(byte[] iv, byte[] sequence, boolean finished, byte[] chunk)
				throws IOException, GeneralSecurityException;
	}

	private final int chunkLength;
	private final byte[] baseNonce;
	private final InputStream source;
	private final CryptOperation cryptOperation;

	private final byte[] sequence;

	private boolean initialized = false;
	private boolean finished = false;
	private boolean noElementEmitted = true;

	private byte[] nextChunk;

	private RuntimeIOException pendingException;

	/**
	 * @param chunkLength
	 *            > 0
	 * @param baseNonce
	 *            not <code>null</code>, length > 0
	 * @param source
	 *            not <code>null</code>
	 * @param cryptOperation
	 *            not <code>null</code>
	 */
	ChunkedInputStreamEnumeration(int chunkLength, byte[] baseNonce, InputStream source, CryptOperation cryptOperation)
	{
		if (chunkLength <= 0)
			throw new IllegalArgumentException("chunkLength <= 0");
		this.chunkLength = chunkLength;
		this.baseNonce = Objects.requireNonNull(baseNonce, "baseNonce");
		if (baseNonce.length <= 0)
			throw new IllegalArgumentException("baseNonce.length <= 0");
		this.source = Objects.requireNonNull(source, "source");
		this.cryptOperation = Objects.requireNonNull(cryptOperation, "cryptOperation");

		this.sequence = new byte[baseNonce.length];
	}

	private void ensureInitialized()
	{
		if (!initialized)
		{
			loadNextChunk();
			initialized = true;
		}
	}

	@Override
	public boolean hasMoreElements()
	{
		ensureInitialized();

		// nextChunk == null && noElementEmittedYet -> source empty, emit empty final chunk
		// nextChunk == null && !noElementEmittedYet -> true end-of-stream

		return nextChunk != null || noElementEmitted;
	}

	@Override
	public InputStream nextElement()
	{
		ensureInitialized();

		if (pendingException != null)
		{
			RuntimeIOException e = pendingException;
			pendingException = null;
			throw e;
		}

		if (nextChunk == null && !noElementEmitted)
			throw new NoSuchElementException();

		boolean currentChunkIsFinal = this.finished;
		byte[] currentChunk = this.nextChunk;

		if (currentChunk == null) // && noElementEmitted
			currentChunk = new byte[0];

		loadNextChunk();

		if (this.nextChunk == null)
			currentChunkIsFinal = true;

		try
		{
			InputStream result = cryptOperation.apply(createNonce(), sequence, currentChunkIsFinal, currentChunk);

			incrementSequence();

			return result;
		}
		catch (IOException e)
		{
			throw new RuntimeIOException(e);
		}
		catch (GeneralSecurityException e)
		{
			throw new RuntimeIOException(new IOException(e.getMessage(), e));
		}
	}

	private void loadNextChunk()
	{
		if (finished)
		{
			nextChunk = null;
			return;
		}

		byte[] buffer = new byte[chunkLength];
		int offset = 0;

		try
		{
			while (offset < chunkLength)
			{
				int read = source.read(buffer, offset, chunkLength - offset);
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
			else if (offset < chunkLength)
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

			// throw new RuntimeIOException(e);
			pendingException = new RuntimeIOException(e);
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
		if (noElementEmitted)
			noElementEmitted = false;

		for (int i = sequence.length - 1; i >= 0; i--)
			if (++sequence[i] != 0)
				return;

		throw new RuntimeIOException("Message limit reached");
	}
}

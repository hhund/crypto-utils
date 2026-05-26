package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.util.Enumeration;

public final class SequenceInputStreamForRuntimeIOException extends SequenceInputStream
{
	public static final SequenceInputStream of(ChunkedInputStreamEnumeration enumeration) throws IOException
	{
		return withRuntimeIOException(() -> new SequenceInputStreamForRuntimeIOException(enumeration));
	}

	/**
	 * @param e
	 *            not <code>null</code>
	 * @throws RuntimeIOException
	 *             if errors occur during the peek operation of the {@link SequenceInputStream} constructor an thus
	 *             reading of the first element
	 */
	private SequenceInputStreamForRuntimeIOException(Enumeration<? extends InputStream> e)
	{
		super(e);
	}

	@Override
	public int read() throws IOException
	{
		return withRuntimeIOException(() -> super.read());
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException
	{
		return withRuntimeIOException(() -> super.read(b, off, len));
	}

	@Override
	public long transferTo(OutputStream out) throws IOException
	{
		return withRuntimeIOException(() -> super.transferTo(out));
	}

	@FunctionalInterface
	private static interface SupplierWithIOException<T>
	{
		T get() throws IOException;
	}

	private static <T> T withRuntimeIOException(SupplierWithIOException<T> withRuntimeIOException) throws IOException
	{
		try
		{
			return withRuntimeIOException.get();
		}
		catch (RuntimeIOException e)
		{
			throw e.asIOException();
		}
	}
}
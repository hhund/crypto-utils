package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.util.Enumeration;

public final class SequenceInputStreamForRuntimeIOException extends SequenceInputStream
{
	public SequenceInputStreamForRuntimeIOException(Enumeration<? extends InputStream> e)
	{
		super(e);
	}

	@Override
	public int read() throws IOException
	{
		try
		{
			return super.read();
		}
		catch (RuntimeIOException e)
		{
			throw e.getCause();
		}
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException
	{
		try
		{
			return super.read(b, off, len);
		}
		catch (RuntimeIOException e)
		{
			throw e.getCause();
		}
	}

	@Override
	public long transferTo(OutputStream out) throws IOException
	{
		try
		{
			return super.transferTo(out);
		}
		catch (RuntimeIOException e)
		{
			throw e.getCause();
		}
	}
}
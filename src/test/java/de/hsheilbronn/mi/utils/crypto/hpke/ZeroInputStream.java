package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.IOException;
import java.io.InputStream;

public final class ZeroInputStream extends InputStream
{
	private final long size;
	private long position = 0;

	public ZeroInputStream(long size)
	{
		this.size = size;
	}

	@Override
	public int read() throws IOException
	{
		if (position >= size)
			return -1;

		position++;
		return 0;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException
	{
		if (position >= size)
			return -1;

		int bytesToRead = (int) Math.min(len, size - position);

		for (int i = 0; i < bytesToRead; i++)
			b[off + i] = 0;

		position += bytesToRead;
		return bytesToRead;
	}

	@Override
	public long skip(long n) throws IOException
	{
		long skipped = Math.min(n, size - position);
		position += skipped;
		return skipped;
	}

	@Override
	public int available() throws IOException
	{
		long remaining = size - position;
		return remaining > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) remaining;
	}
}

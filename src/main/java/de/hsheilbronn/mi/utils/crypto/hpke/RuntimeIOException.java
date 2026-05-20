package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.IOException;

public final class RuntimeIOException extends RuntimeException
{
	private static final long serialVersionUID = 1L;

	public RuntimeIOException(IOException cause)
	{
		super(cause);
	}

	@Override
	public synchronized IOException getCause()
	{
		return (IOException) super.getCause();
	}
}
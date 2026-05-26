package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.IOException;
import java.util.Objects;

public final class RuntimeIOException extends RuntimeException
{
	private static final long serialVersionUID = 1L;

	public RuntimeIOException(IOException cause)
	{
		super(Objects.requireNonNull(cause, "cause"));
	}

	/**
	 * @return the wrapped {@link IOException}
	 */
	public IOException asIOException()
	{
		return (IOException) super.getCause();
	}
}
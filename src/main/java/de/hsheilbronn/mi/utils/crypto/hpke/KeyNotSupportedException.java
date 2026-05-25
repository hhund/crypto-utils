package de.hsheilbronn.mi.utils.crypto.hpke;

public final class KeyNotSupportedException extends Exception
{
	private static final long serialVersionUID = 1L;

	public KeyNotSupportedException(String message)
	{
		super(message);
	}
}
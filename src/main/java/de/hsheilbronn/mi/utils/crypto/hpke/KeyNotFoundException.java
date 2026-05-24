package de.hsheilbronn.mi.utils.crypto.hpke;

public final class KeyNotFoundException extends Exception
{
	private static final long serialVersionUID = 1L;

	public KeyNotFoundException(String message)
	{
		super(message);
	}
}
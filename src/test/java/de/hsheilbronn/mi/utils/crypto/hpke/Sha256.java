package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class Sha256
{
	private Sha256()
	{
	}

	public static byte[] digest(byte[] bytes)
	{
		try
		{
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			return digest.digest(bytes);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new RuntimeException(e);
		}
	}
}

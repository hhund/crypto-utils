package de.hsheilbronn.mi.utils.crypto.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Objects;

public final class KeyStoreWriter
{
	private KeyStoreWriter()
	{
	}

	/**
	 * @param keyStore
	 *            not <code>null</code>
	 * @param password
	 *            not <code>null</code> if {@link KeyStore} type jks
	 * @return {@link KeyStore} as {@link String}
	 */
	public static byte[] write(KeyStore keyStore, char[] password)
	{
		try (ByteArrayOutputStream out = new ByteArrayOutputStream())
		{
			write(keyStore, password, out);

			return out.toByteArray();
		}
		catch (IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	/**
	 * @param keyStore
	 *            not <code>null</code>
	 * @param password
	 *            not <code>null</code> if {@link KeyStore} type jks
	 * @param file
	 *            not <code>null</code>
	 */
	public static void write(KeyStore keyStore, char[] password, Path file) throws IOException
	{
		Objects.requireNonNull(file, "file");

		try (OutputStream out = Files.newOutputStream(file))
		{
			write(keyStore, password, out);
		}
	}

	/**
	 * @param keyStore
	 *            not <code>null</code>
	 * @param password
	 *            not <code>null</code> if {@link KeyStore} type jks
	 * @param out
	 *            not <code>null</code>
	 */
	public static void write(KeyStore keyStore, char[] password, OutputStream out) throws IOException
	{
		Objects.requireNonNull(keyStore, "keyStore");
		Objects.requireNonNull(out, "out");

		if ("jks".equals(keyStore.getType()))
			Objects.requireNonNull(password, "password");

		try (out)
		{
			keyStore.store(out, password);
		}
		catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e)
		{
			throw new IOException(e);
		}
	}
}

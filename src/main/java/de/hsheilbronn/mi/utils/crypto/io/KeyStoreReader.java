package de.hsheilbronn.mi.utils.crypto.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Objects;

public final class KeyStoreReader
{
	private static final String KEY_STORE_TYPE_PKCS12 = "pkcs12";
	private static final String KEY_STORE_TYPE_JKS = "jks";

	private KeyStoreReader()
	{
	}

	private static KeyStore read(String keyStoreType, byte[] content, char[] password)
	{
		Objects.requireNonNull(content, "content");

		try (InputStream stream = new ByteArrayInputStream(content))
		{
			return read(keyStoreType, stream, password);
		}
		catch (IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	private static KeyStore read(String keyStoreType, Path file, char[] password) throws IOException
	{
		Objects.requireNonNull(file, "file");

		try (InputStream stream = Files.newInputStream(file))
		{
			return read(keyStoreType, stream, password);
		}
	}

	private static KeyStore read(String keyStoreType, InputStream stream, char[] password) throws IOException
	{
		Objects.requireNonNull(keyStoreType, "keyStoreType");
		Objects.requireNonNull(stream, "stream");

		try
		{
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(stream, password);

			return keyStore;
		}
		catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e)
		{
			throw new IOException(e);
		}
	}

	/**
	 * @param content
	 *            not <code>null</code>
	 * @param password
	 *            if not <code>null</code> used to check the integrity of the keystore
	 * @return jks {@link KeyStore}
	 * @see KeyStore#load(InputStream, char[])
	 */
	public static KeyStore readJks(byte[] content, char[] password)
	{
		return read(KEY_STORE_TYPE_JKS, content, password);
	}

	/**
	 * @param file
	 *            not <code>null</code>
	 * @param password
	 *            if not <code>null</code> used to check the integrity of the keystore
	 * @return jks {@link KeyStore}
	 * @throws IOException
	 * @see KeyStore#load(InputStream, char[])
	 */
	public static KeyStore readJks(Path file, char[] password) throws IOException
	{
		return read(KEY_STORE_TYPE_JKS, file, password);
	}

	/**
	 * @param stream
	 *            not <code>null</code>
	 * @param password
	 *            if not <code>null</code> used to check the integrity of the keystore
	 * @return jks {@link KeyStore}
	 * @throws IOException
	 * @see KeyStore#load(InputStream, char[])
	 */
	public static KeyStore readJks(InputStream stream, char[] password) throws IOException
	{
		return read(KEY_STORE_TYPE_JKS, stream, password);
	}

	/**
	 * @param content
	 *            not <code>null</code>
	 * @param password
	 *            if not <code>null</code> used to check the integrity of the keystore
	 * @return pkcs12 {@link KeyStore}
	 * @see KeyStore#load(InputStream, char[])
	 */
	public static KeyStore readPkcs12(byte[] content, char[] password)
	{
		return read(KEY_STORE_TYPE_PKCS12, content, password);
	}

	/**
	 * @param file
	 *            not <code>null</code>
	 * @param password
	 *            if not <code>null</code> used to check the integrity of the keystore
	 * @return pkcs12 {@link KeyStore}
	 * @throws IOException
	 * @see KeyStore#load(InputStream, char[])
	 */
	public static KeyStore readPkcs12(Path file, char[] password) throws IOException
	{
		return read(KEY_STORE_TYPE_PKCS12, file, password);
	}

	/**
	 * @param stream
	 *            not <code>null</code>
	 * @param password
	 *            if not <code>null</code> used to check the integrity of the keystore
	 * @return pkcs12 {@link KeyStore}
	 * @throws IOException
	 * @see KeyStore#load(InputStream, char[])
	 */
	public static KeyStore readPkcs12(InputStream stream, char[] password) throws IOException
	{
		return read(KEY_STORE_TYPE_PKCS12, stream, password);
	}
}

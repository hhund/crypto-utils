/**
 * 
 */
package de.rwh.utils.crypto.io;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * @author hhund
 * 
 */
public final class CertificateReader
{
	public static KeyStore fromPkcs12(Path file, String password) throws KeyStoreException, CertificateException,
			IOException, NoSuchAlgorithmException
	{
		try (InputStream stream = Files.newInputStream(file))
		{
			return fromPkcs12(password, stream);
		}
	}

	public static KeyStore fromPkcs12(String password, InputStream stream) throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException
	{
		KeyStore keyStore = KeyStore.getInstance("pkcs12");
		keyStore.load(stream, password.toCharArray());

		return keyStore;
	}

	public static KeyStore fromCer(Path file, String alias) throws NoSuchAlgorithmException, CertificateException,
			IOException, KeyStoreException
	{
		try (InputStream stream = Files.newInputStream(file))
		{
			return fromCer(alias, stream);
		}
	}

	public static KeyStore fromCer(String alias, InputStream stream) throws CertificateException, KeyStoreException,
			IOException, NoSuchAlgorithmException
	{
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
		Certificate certificate = certificateFactory.generateCertificate(stream);

		KeyStore keyStore = KeyStore.getInstance("jks");
		keyStore.load(null, null);
		keyStore.setCertificateEntry(alias, certificate);

		return keyStore;
	}

	public static KeyStore allFromCer(Path file) throws NoSuchAlgorithmException, CertificateException, IOException,
			KeyStoreException
	{
		try (InputStream stream = Files.newInputStream(file))
		{
			return allFromCer(stream);
		}
	}

	public static KeyStore allFromCer(InputStream stream) throws CertificateException, KeyStoreException, IOException,
			NoSuchAlgorithmException
	{
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
		Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(stream);

		KeyStore keyStore = KeyStore.getInstance("jks");
		keyStore.load(null, null);

		for (Certificate c : certificates)
			keyStore.setCertificateEntry(((X509Certificate) c).getSubjectDN().getName(), c);

		return keyStore;
	}

	private CertificateReader()
	{
	}
}

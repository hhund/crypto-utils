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
			KeyStore keyStore = KeyStore.getInstance("pkcs12");
			keyStore.load(stream, password.toCharArray());

			return keyStore;
		}
	}

	public static KeyStore fromCer(Path file, String alias) throws NoSuchAlgorithmException, CertificateException,
			IOException, KeyStoreException
	{
		try (InputStream stream = Files.newInputStream(file))
		{
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
			Certificate certificate = certificateFactory.generateCertificate(stream);

			KeyStore keyStore = KeyStore.getInstance("jks");
			keyStore.load(null, null);
			keyStore.setCertificateEntry(alias, certificate);

			return keyStore;
		}
	}

	private CertificateReader()
	{
	}
}

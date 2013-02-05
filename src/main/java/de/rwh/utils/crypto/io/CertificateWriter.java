/**
 * 
 */
package de.rwh.utils.crypto.io;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * @author hhund
 * 
 */
public final class CertificateWriter
{
	public static void toPkcs12(Path file, KeyStore keyStore, String password)
	{
		if (!"pkcs12".equalsIgnoreCase(keyStore.getType()))
			throw new IllegalArgumentException("KeyStore type must be pkcs12");

		try (OutputStream stream = Files.newOutputStream(file))
		{
			keyStore.store(stream, password.toCharArray());
		}
		catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e)
		{
			throw new RuntimeException(e);
		}
	}

	public static void toCer(Path file, KeyStore keyStore, String certificateAlias)
	{
		try
		{
			Certificate certificate = keyStore.getCertificate(certificateAlias);
			if (certificate == null)
				throw new IllegalArgumentException(String.format("No Certificate with alias %s", certificateAlias));

			byte[] encoded = certificate.getEncoded();

			Files.write(file, encoded);
		}
		catch (IllegalArgumentException e)
		{
			throw e;
		}
		catch (KeyStoreException | CertificateEncodingException | IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	private CertificateWriter()
	{
	}
}

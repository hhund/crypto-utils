package de.rwh.utils.crypto.io;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import de.rwh.utils.crypto.CertificateHelper;

public final class CertificateWriter
{
	public static void toPkcs12(Path file, PrivateKey privateKey, String password, Certificate certificate,
			Certificate caCertificate, String certificateAlias) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException
	{
		KeyStore keyStore = CertificateHelper.toPkcs12KeyStore(privateKey, new Certificate[] { certificate,
				caCertificate }, certificateAlias, password);

		toPkcs12(file, keyStore, password);
	}

	public static void toPkcs12(Path file, KeyStore keyStore, String password) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException
	{
		if (!"pkcs12".equalsIgnoreCase(keyStore.getType()))
			throw new IllegalArgumentException("KeyStore type must be pkcs12");

		try (OutputStream stream = Files.newOutputStream(file))
		{
			keyStore.store(stream, password.toCharArray());
		}
	}

	public static void toCer(Path file, KeyStore keyStore, String certificateAlias) throws KeyStoreException,
			CertificateEncodingException, IOException
	{
		Certificate certificate = keyStore.getCertificate(certificateAlias);
		if (certificate == null)
			throw new IllegalArgumentException(String.format("No Certificate with alias %s", certificateAlias));

		toCer(file, certificate);
	}

	public static void toCer(Path file, Certificate certificate) throws IOException, CertificateEncodingException
	{
		byte[] encoded = certificate.getEncoded();

		Files.write(file, encoded);
	}

	public static void toCer(Path file, Certificate[] certificates) throws IOException, CertificateEncodingException
	{
		try (BufferedOutputStream out = new BufferedOutputStream(Files.newOutputStream(file)))
		{
			for (Certificate c : certificates)
			{
				byte[] encoded = c.getEncoded();
				out.write(encoded);
			}
		}
	}

	private CertificateWriter()
	{
	}
}

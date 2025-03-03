package de.hsheilbronn.mi.utils.crypto.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.crypto.EncryptedPrivateKeyInfo;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest;

public final class PemReader
{
	private PemReader()
	{
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return certificate
	 * @throws IOException
	 *             if the given {@link String} does not contain a pem encoded certificate, more than one or is not
	 *             readable or parsable
	 */
	public static X509Certificate readCertificate(String pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))
		{
			return readCertificate(in);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return certificate
	 * @throws IOException
	 *             if the given file does not contain a pem encoded certificate, more than one or is not readable or
	 *             parsable
	 */
	public static X509Certificate readCertificate(Path pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = Files.newInputStream(pem))
		{
			return readCertificate(in);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return certificate
	 * @throws IOException
	 *             if the given {@link InputStream} does not contain a pem encoded certificate, more than one or is not
	 *             readable or parsable
	 */
	public static X509Certificate readCertificate(InputStream pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (Reader reader = new InputStreamReader(pem); PEMParser parser = new PEMParser(reader))
		{
			Object o = parser.readObject();

			if (o instanceof X509CertificateHolder c)
			{
				try
				{
					return new JcaX509CertificateConverter().getCertificate(c);
				}
				catch (CertificateException e)
				{
					throw new IOException(e);
				}
			}
			else
				throw new IOException("Read pem object not a certificate");
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return list of certificates
	 * @throws IOException
	 *             if the given {@link String} does not contain pem encoded certificates or is not readable or one is
	 *             not parsable
	 */
	public static List<X509Certificate> readCertificates(String pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))
		{
			return readCertificates(in);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return list of certificates
	 * @throws IOException
	 *             if the given file does not contain pem encoded certificates or is not readable or one is not parsable
	 */
	public static List<X509Certificate> readCertificates(Path pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = Files.newInputStream(pem))
		{
			return readCertificates(in);
		}
	}

	/**
	 * @param pem
	 * @return list of certificates
	 * @throws IOException
	 *             if the given {@link InputStream} does not contain pem encoded certificates or is not readable or one
	 *             is not parsable
	 */
	public static List<X509Certificate> readCertificates(InputStream pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (Reader reader = new InputStreamReader(pem); PEMParser parser = new PEMParser(reader))
		{
			List<X509Certificate> certificates = new ArrayList<>();

			Object o;
			while ((o = parser.readObject()) != null)
			{
				if (o instanceof X509CertificateHolder c)
				{
					try
					{
						certificates.add(new JcaX509CertificateConverter().getCertificate(c));
					}
					catch (CertificateException e)
					{
						throw new IOException(e);
					}
				}
				else
					throw new IOException("Read pem object not a certificate");
			}

			return certificates;
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return certificate revocation list
	 * @throws IOException
	 *             if the given {@link String} does not contain a pem encoded certificate revocation list, more than one
	 *             or is not readable or parsable
	 */
	public static X509CRL readCertificateRevocationList(String pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))
		{
			return readCertificateRevocationList(in);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return certificate revocation list
	 * @throws IOException
	 *             if the given file does not contain a pem encoded certificate revocation list, more than one or is not
	 *             readable or parsable
	 */
	public static X509CRL readCertificateRevocationList(Path pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = Files.newInputStream(pem))
		{
			return readCertificateRevocationList(in);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return certificate revocation list
	 * @throws IOException
	 *             if the given {@link InputStream} does not contain a pem encoded certificate revocation list, more
	 *             than one or is not readable or parsable
	 */
	public static X509CRL readCertificateRevocationList(InputStream pem) throws IOException
	{
		try (Reader reader = new InputStreamReader(pem); PEMParser parser = new PEMParser(reader))
		{
			Object o = parser.readObject();
			if (o instanceof X509CRLHolder c)
			{
				try
				{
					return new JcaX509CRLConverter().getCRL(c);
				}
				catch (CRLException e)
				{
					throw new IOException(e);
				}
			}
			else
				throw new IOException("Not a X.509 certificate revocation list, but " + o.getClass().getName());
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return certification request
	 * @throws IOException
	 *             if the given {@link String} does not contain a pem encoded certificate request, more than one or is
	 *             not readable or parsable
	 */
	public static CertificationRequest readCertificationRequest(String pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))
		{
			return readCertificationRequest(in);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return certification request
	 * @throws IOException
	 *             if the given file does not contain a pem encoded certificate request, more than one or is not
	 *             readable or parsable
	 */
	public static CertificationRequest readCertificationRequest(Path pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = Files.newInputStream(pem))
		{
			return readCertificationRequest(in);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return certification request
	 * @throws IOException
	 *             if the given {@link InputStream} does not contain a pem encoded certificate request, more than one or
	 *             is not readable or parsable
	 */
	public static CertificationRequest readCertificationRequest(InputStream pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (Reader reader = new InputStreamReader(pem); PEMParser parser = new PEMParser(reader))
		{
			Object o = parser.readObject();

			if (o instanceof PKCS10CertificationRequest r)
				return CertificationRequest.of(new JcaPKCS10CertificationRequest(r));
			else
				throw new IOException("Read pem object not a certificate request, but " + o.getClass().getName());
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return private key
	 * @throws IOException
	 *             if the given {@link String} does not contain a pem encoded, unencrypted private key, more than one or
	 *             is not readable or parsable
	 */
	public static PrivateKey readPrivateKey(String pem) throws IOException
	{
		try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))
		{
			return readPrivateKey(in);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return private key
	 * @throws IOException
	 *             if the given file does not contain a pem encoded, unencrypted private key, more than one or is not
	 *             readable or parsable
	 */
	public static PrivateKey readPrivateKey(Path pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = Files.newInputStream(pem))
		{
			return readPrivateKey(in);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @return private key
	 * @throws IOException
	 *             if the given {@link InputStream} does not contain a pem encoded, unencrypted private key, more than
	 *             one or is not readable or parsable
	 */
	public static PrivateKey readPrivateKey(InputStream pem) throws IOException
	{
		return readPrivateKey(pem, null);
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @param password
	 *            if key encrypted not <code>null</code>
	 * @return private key
	 * @throws IOException
	 *             if the given {@link String} does not contain a pem encoded private key, more than one or is not
	 *             readable or parsable
	 */
	public static PrivateKey readPrivateKey(String pem, char[] password) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))
		{
			return readPrivateKey(in, password);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @param password
	 *            if key encrypted not <code>null</code>
	 * @return private key
	 * @throws IOException
	 *             if the given file does not contain a pem encoded private key, more than one or is not readable or
	 *             parsable
	 */
	public static PrivateKey readPrivateKey(Path pem, char[] password) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = Files.newInputStream(pem))
		{
			return readPrivateKey(in, password);
		}
	}

	/**
	 * @param pem
	 *            not <code>null</code>
	 * @param password
	 *            if key encrypted not <code>null</code>
	 * @return private key
	 * @throws IOException
	 *             if the given {@link InputStream} does not contain a pem encoded private key, more than one or is not
	 *             readable or parsable
	 */
	public static PrivateKey readPrivateKey(InputStream pem, char[] password) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (Reader reader = new InputStreamReader(pem); PEMParser parser = new PEMParser(reader))
		{
			Object o = parser.readObject();

			// pkcs8 encrypted
			if (o instanceof PKCS8EncryptedPrivateKeyInfo p)
			{
				Objects.requireNonNull(password, "pkcs8 encrypted private key, password required");

				InputDecryptorProvider decryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
						.setProvider(new BouncyCastleProvider()).build(password);

				try
				{
					PrivateKeyInfo privateKey = p.decryptPrivateKeyInfo(decryptorProvider);
					return new JcaPEMKeyConverter().getPrivateKey(privateKey);
				}
				catch (PEMException | PKCSException e)
				{
					throw new IOException(e);
				}
			}

			// pkcs1 no encryption
			else if (o instanceof PrivateKeyInfo i)
			{
				return new JcaPEMKeyConverter().getPrivateKey(i);
			}

			// openssl classic encrypted
			else if (o instanceof PEMEncryptedKeyPair p)
			{
				Objects.requireNonNull(password, "openSSL classic encrypted private key, password required");

				PEMKeyPair keyPair = p.decryptKeyPair(new BcPEMDecryptorProvider(password));

				PrivateKeyInfo privateKey = keyPair.getPrivateKeyInfo();
				return new JcaPEMKeyConverter().getPrivateKey(privateKey);
			}

			// openssl no encryption
			else if (o instanceof PEMKeyPair p)
			{
				PrivateKeyInfo privateKey = p.getPrivateKeyInfo();
				return new JcaPEMKeyConverter().getPrivateKey(privateKey);
			}

			else
				throw new IOException(o.getClass().getName() + " not supported");
		}
	}

	public static EncryptedPrivateKeyInfo readPkcs8EncryptedPrivateKey(String pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))
		{
			return readPkcs8EncryptedPrivateKey(in);
		}
	}

	public static EncryptedPrivateKeyInfo readPkcs8EncryptedPrivateKey(Path pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (InputStream in = Files.newInputStream(pem))
		{
			return readPkcs8EncryptedPrivateKey(in);
		}
	}

	public static EncryptedPrivateKeyInfo readPkcs8EncryptedPrivateKey(InputStream pem) throws IOException
	{
		Objects.requireNonNull(pem, "pem");

		try (Reader reader = new InputStreamReader(pem); PEMParser parser = new PEMParser(reader))
		{
			Object o = parser.readObject();

			// pkcs8 encrypted
			if (o instanceof PKCS8EncryptedPrivateKeyInfo p)
			{
				try
				{
					String algorithmName = new DefaultAlgorithmNameFinder()
							.getAlgorithmName(p.getEncryptionAlgorithm());
					return new EncryptedPrivateKeyInfo(algorithmName, p.getEncryptedData());
				}
				catch (NoSuchAlgorithmException e)
				{
					throw new IOException("Encryption algorithm not supported", e);
				}
			}

			else
				throw new IOException(o.getClass().getName() + " not supported");
		}
	}
}
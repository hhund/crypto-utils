/**
 * 
 */
package de.rwh.utils.crypto.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author hhund
 * 
 */
public final class PemIo extends AbstractCertIo
{
	public static final String PEM_FILE_EXTENSION = ".pem";

	private static final Charset CHAR_SET = StandardCharsets.UTF_8;
	private static final int LINE_LENGTH = 64;

	private static final String PRIVATE_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
	private static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";

	private static final String PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
	private static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

	private static final String CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----";
	private static final String CERTIFICATE_END = "-----END CERTIFICATE-----";

	private PemIo()
	{
	}

	public static void writeX509CertificateToPem(X509Certificate certificate, Path pemFile) throws IOException,
			CertificateEncodingException
	{
		byte[] encodedCertificate = certificate.getEncoded();

		writeEncoded(encodedCertificate, pemFile, CERTIFICATE_BEGIN, CERTIFICATE_END, CHAR_SET, LINE_LENGTH);
	}

	public static String writeX509Certificate(X509Certificate certificate) throws IOException,
			CertificateEncodingException
	{
		byte[] encodedCertificate = certificate.getEncoded();

		return writeEncoded(encodedCertificate, CERTIFICATE_BEGIN, CERTIFICATE_END, CHAR_SET, LINE_LENGTH);
	}

	public static void writePublicKeyToPem(RSAPublicKey publicKey, Path pemFile) throws IOException
	{
		byte[] encodedPublicKey = publicKey.getEncoded();

		writeEncoded(encodedPublicKey, pemFile, PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, CHAR_SET, LINE_LENGTH);
	}

	public static void writePrivateKeyToPem(RSAPrivateCrtKey privateKey, Path pemFile) throws IOException
	{
		byte[] encodedPrivateKey = privateKey.getEncoded();

		writeEncoded(encodedPrivateKey, pemFile, PRIVATE_KEY_BEGIN, PRIVATE_KEY_END, CHAR_SET, LINE_LENGTH);
	}

	public static X509Certificate readX509CertificateFromPem(Path pemFile) throws IOException, CertificateException
	{
		byte[] encodedCertificate = readEncoded(pemFile, CERTIFICATE_BEGIN, CERTIFICATE_END, CHAR_SET, LINE_LENGTH);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(encodedCertificate));

		if (certificate instanceof X509Certificate)
			return (X509Certificate) certificate;
		else
			throw new IllegalStateException("certificate not a X509Certificate");
	}

	public static X509Certificate readX509CertificateFromPem(String content) throws IOException,
			CertificateException
	{
		byte[] encodedCertificate = readEncoded(content, CERTIFICATE_BEGIN, CERTIFICATE_END);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(encodedCertificate));

		if (certificate instanceof X509Certificate)
			return (X509Certificate) certificate;
		else
			throw new IllegalStateException("certificate not a X509Certificate");
	}

	public static RSAPublicKey readPublicKeyFromPem(Path pemFile) throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException
	{
		byte[] encodedPublicKey = readEncoded(pemFile, PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, CHAR_SET, LINE_LENGTH);

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey publicKey = kf.generatePublic(keySpec);

		if (publicKey instanceof RSAPublicKey)
			return (RSAPublicKey) publicKey;
		else
			throw new IllegalStateException("public key not a RSAPublicKey");
	}

	public static RSAPrivateCrtKey readPrivateKeyFromPem(Path pemFile) throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException
	{
		byte[] encodedPrivateKey = readEncoded(pemFile, PRIVATE_KEY_BEGIN, PRIVATE_KEY_END, CHAR_SET, LINE_LENGTH);

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = kf.generatePrivate(keySpec);

		if (privateKey instanceof RSAPrivateCrtKey)
			return (RSAPrivateCrtKey) privateKey;
		else
			throw new IllegalStateException("private key not a RSAPrivateCrtKey");
	}
}

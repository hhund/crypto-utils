package de.hsheilbronn.mi.utils.crypto.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PemIo extends AbstractCertIo
{
	private static final Logger logger = LoggerFactory.getLogger(PemIo.class);

	public static final String PEM_FILE_EXTENSION = ".pem";

	private static final Charset CHAR_SET = StandardCharsets.UTF_8;
	private static final int LINE_LENGTH = 64;

	private static final String PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
	private static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

	private static final String CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----";
	private static final String CERTIFICATE_END = "-----END CERTIFICATE-----";

	private PemIo()
	{
	}

	public static void writeX509CertificateToPem(X509Certificate certificate, Path pemFile)
			throws IOException, CertificateEncodingException
	{
		byte[] encodedCertificate = certificate.getEncoded();

		writeEncoded(encodedCertificate, pemFile, CERTIFICATE_BEGIN, CERTIFICATE_END, CHAR_SET, LINE_LENGTH);
	}

	public static String writeX509Certificate(X509Certificate certificate)
			throws IOException, CertificateEncodingException
	{
		byte[] encodedCertificate = certificate.getEncoded();

		return writeEncoded(encodedCertificate, CERTIFICATE_BEGIN, CERTIFICATE_END, CHAR_SET, LINE_LENGTH);
	}

	public static void writePublicKeyToPem(RSAPublicKey publicKey, Path pemFile) throws IOException
	{
		byte[] encodedPublicKey = publicKey.getEncoded();

		writeEncoded(encodedPublicKey, pemFile, PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, CHAR_SET, LINE_LENGTH);
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

	public static X509Certificate readX509CertificateFromPem(String content) throws IOException, CertificateException
	{
		byte[] encodedCertificate = readEncoded(content, CERTIFICATE_BEGIN, CERTIFICATE_END);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(encodedCertificate));

		if (certificate instanceof X509Certificate)
			return (X509Certificate) certificate;
		else
			throw new IllegalStateException("certificate not a X509Certificate");
	}

	public static RSAPublicKey readPublicKeyFromPem(Path pemFile)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
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

	/**
	 * will use a new {@link BouncyCastleProvider}
	 * 
	 * @param pemFile
	 *            not <code>null</code>
	 * @return the private key
	 * @throws IOException
	 *             if IO errors occur or the <b>pemFile</b> is not a private key or the given <b>pemFile</b> is
	 *             encrypted
	 * @throws PKCSException
	 * @see #readPrivateKeyFromPem(Path, char[])
	 */
	public static PrivateKey readPrivateKeyFromPem(Path pemFile) throws IOException, PKCSException
	{
		return readPrivateKeyFromPem(pemFile, null);
	}

	/**
	 * @param provider
	 *            not <code>null</code>
	 * @param pemFile
	 *            not <code>null</code>
	 * @return the private key
	 * @throws IOException
	 *             if IO errors occur or the <b>pemFile</b> is not a private key or the given <b>pemFile</b> is
	 *             encrypted
	 * @throws PKCSException
	 * @see #readPrivateKeyFromPem(BouncyCastleProvider, Path, char[])
	 */
	public static PrivateKey readPrivateKeyFromPem(BouncyCastleProvider provider, Path pemFile)
			throws IOException, PKCSException
	{
		return readPrivateKeyFromPem(provider, pemFile, null);
	}

	/**
	 * will use a new {@link BouncyCastleProvider}
	 * 
	 * @param pemFile
	 * @param password
	 * @return
	 * @throws IOException
	 * @throws PKCSException
	 * @see #readPrivateKeyFromPem(BouncyCastleProvider, Path, char[])
	 */
	public static PrivateKey readPrivateKeyFromPem(Path pemFile, char[] password) throws IOException, PKCSException
	{
		return readPrivateKeyFromPem(new BouncyCastleProvider(), pemFile, password);
	}

	/**
	 * @param provider
	 *            not <code>null</code>
	 * @param pemFile
	 *            not <code>null</code>
	 * @param password
	 *            not <code>null</code> if <b>pemFile</b> is encrypted, will be ignored if <b>pemFile</b> is not
	 *            encrypted
	 * @return the private key
	 * @throws IOException
	 *             if IO errors occur or the <b>pemFile</b> is not a private key or the given <b>password</b> is
	 *             <code>null</code> and the <b>pemFile</b> is encrypted
	 * @throws PKCSException
	 *             if errors occur during private key decryption
	 */
	public static PrivateKey readPrivateKeyFromPem(BouncyCastleProvider provider, Path pemFile, char[] password)
			throws IOException, PKCSException
	{
		Objects.requireNonNull(provider, "provider");
		Objects.requireNonNull(pemFile, "pemFile");

		final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(provider);

		try (InputStream in = Files.newInputStream(pemFile);
				Reader reader = new InputStreamReader(in);
				PEMParser pemParser = new PEMParser(reader))
		{
			Object o = pemParser.readObject();
			if (o instanceof PKCS8EncryptedPrivateKeyInfo)
			{
				if (password == null)
					throw new IOException("password is null");

				PKCS8EncryptedPrivateKeyInfo encryptedPrivateKey = (PKCS8EncryptedPrivateKeyInfo) o;

				InputDecryptorProvider decryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
						.setProvider(provider).build(password);

				PrivateKeyInfo privateKey = encryptedPrivateKey.decryptPrivateKeyInfo(decryptorProvider);
				return converter.getPrivateKey(privateKey);
			}
			else if (o instanceof PrivateKeyInfo)
			{
				if (password != null)
					logger.warn("Private key not encrypted, ignoring password");

				PrivateKeyInfo privateKey = (PrivateKeyInfo) o;
				return converter.getPrivateKey(privateKey);
			}
			else if (o instanceof PEMEncryptedKeyPair)
			{
				if (password == null)
					throw new IOException("password is null");

				PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) o;
				PEMKeyPair keyPair = encryptedKeyPair.decryptKeyPair(new BcPEMDecryptorProvider(password));

				PrivateKeyInfo privateKey = keyPair.getPrivateKeyInfo();
				return converter.getPrivateKey(privateKey);
			}
			else if (o instanceof PEMKeyPair)
			{
				if (password != null)
					logger.warn("Key pair not encrypted, ignoring password");

				PEMKeyPair keyPair = (PEMKeyPair) o;

				PrivateKeyInfo privateKey = keyPair.getPrivateKeyInfo();
				return converter.getPrivateKey(privateKey);
			}
			else
			{
				throw new IOException(o.getClass().getName() + " not supported");
			}
		}
	}

	public static void write3DesEncryptedPrivateKeyToPkcs8(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey, char[] password) throws OperatorCreationException, IOException
	{
		writeEncryptedPrivateKeyToPkcs8(provider, pemFile, privateKey, password, PKCSObjectIdentifiers.des_EDE3_CBC);
	}

	public static void writeAes128EncryptedPrivateKeyToPkcs8(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey, char[] password) throws OperatorCreationException, IOException
	{
		writeEncryptedPrivateKeyToPkcs8(provider, pemFile, privateKey, password, NISTObjectIdentifiers.id_aes128_CBC);
	}

	public static void writeAes256EncryptedPrivateKeyToPkcs8(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey, char[] password) throws OperatorCreationException, IOException
	{
		writeEncryptedPrivateKeyToPkcs8(provider, pemFile, privateKey, password, NISTObjectIdentifiers.id_aes256_CBC);
	}

	private static void writeEncryptedPrivateKeyToPkcs8(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey, char[] password, ASN1ObjectIdentifier keyEncryptionAlg)
			throws OperatorCreationException, IOException
	{
		OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(
				new PBKDF2Config.Builder().withPRF(PBKDF2Config.PRF_SHA256).withIterationCount(2048).build(),
				keyEncryptionAlg).setProvider(provider).build(password);

		writePrivateKeyToPkcs8(provider, pemFile, privateKey, password, encryptor);
	}

	public static void writeNotEncryptedPrivateKeyToPkcs8(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey) throws OperatorCreationException, IOException
	{
		writePrivateKeyToPkcs8(provider, pemFile, privateKey, null, null);
	}

	private static void writePrivateKeyToPkcs8(BouncyCastleProvider provider, Path pemFile, PrivateKey privateKey,
			char[] password, OutputEncryptor encryptor) throws OperatorCreationException, IOException
	{
		try (OutputStream out = Files.newOutputStream(pemFile);
				OutputStreamWriter writer = new OutputStreamWriter(out);
				PemWriter pemWriter = new PemWriter(writer))
		{
			PrivateKeyInfo info = PrivateKeyInfo.getInstance(privateKey.getEncoded());
			pemWriter.writeObject(new PKCS8Generator(info, encryptor));
		}
	}

	public static void write3DesEncryptedPrivateKeyToOpenSslClassicPem(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey, char[] password) throws OperatorCreationException, IOException
	{
		writeEncryptedPrivateKeyToOpenSslClassicPem(provider, pemFile, privateKey, password, "DES-EDE3-CBC");
	}

	public static void writeAes128EncryptedPrivateKeyToOpenSslClassicPem(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey, char[] password) throws OperatorCreationException, IOException
	{
		writeEncryptedPrivateKeyToOpenSslClassicPem(provider, pemFile, privateKey, password, "AES-128-CBC");
	}

	public static void writeAes256EncryptedPrivateKeyToOpenSslClassicPem(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey, char[] password) throws OperatorCreationException, IOException
	{
		writeEncryptedPrivateKeyToOpenSslClassicPem(provider, pemFile, privateKey, password, "AES-256-CBC");
	}

	private static void writeEncryptedPrivateKeyToOpenSslClassicPem(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey, char[] password, String algorithm) throws OperatorCreationException, IOException
	{
		PEMEncryptor encryptor = new JcePEMEncryptorBuilder(algorithm).setProvider(provider).build(password);
		writePrivateKeyToOpenSslClassicPem(provider, pemFile, privateKey, password, encryptor);
	}

	public static void writeNotEncryptedPrivateKeyToOpenSslClassicPem(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey) throws OperatorCreationException, IOException
	{
		writePrivateKeyToOpenSslClassicPem(provider, pemFile, privateKey, null, null);
	}

	private static void writePrivateKeyToOpenSslClassicPem(BouncyCastleProvider provider, Path pemFile,
			PrivateKey privateKey, char[] password, PEMEncryptor encryptor)
			throws OperatorCreationException, IOException
	{
		try (OutputStream out = Files.newOutputStream(pemFile);
				OutputStreamWriter writer = new OutputStreamWriter(out);
				PemWriter pemWriter = new PemWriter(writer))
		{
			PrivateKeyInfo info = PrivateKeyInfo.getInstance(privateKey.getEncoded());
			pemWriter.writeObject(new MiscPEMGenerator(info, encryptor));
		}
	}
}

package de.rwh.utils.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.After;
import org.junit.Test;

import de.rwh.utils.crypto.io.CertificateReader;
import de.rwh.utils.crypto.io.PemIo;

public class PemIoTest
{
	private static final BouncyCastleProvider provider = new BouncyCastleProvider();
	private static final char[] password = "password".toCharArray();

	private Path pemFile;

	@After
	public void after() throws IOException
	{
		if (pemFile != null)
			Files.deleteIfExists(pemFile);
	}

	private Path newFile()
	{
		return Paths.get("target", UUID.randomUUID().toString() + ".pem");
	}

	@Test
	public void testWriteReadPrivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException,
			PKCSException, OperatorCreationException
	{
		pemFile = newFile();

		PrivateKey privateKey = CertificateHelper.createKeyPair(CertificateHelper.DEFAULT_KEY_ALGORITHM, 2048)
				.getPrivate();

		PemIo.writeNotEncryptedPrivateKeyToOpenSslClassicPem(provider, pemFile, privateKey);

		PrivateKey readPrivateKey = PemIo.readPrivateKeyFromPem(pemFile);
		assertEquals(privateKey, readPrivateKey);
	}

	@Test
	public void testWriteReadPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
	{
		pemFile = newFile();

		RSAPublicKey publicKey = (RSAPublicKey) CertificateHelper
				.createKeyPair(CertificateHelper.DEFAULT_KEY_ALGORITHM, 2048).getPublic();

		PemIo.writePublicKeyToPem(publicKey, pemFile);

		RSAPublicKey readPublicKey = PemIo.readPublicKeyFromPem(pemFile);

		assertEquals(publicKey, readPublicKey);
	}

	@Test
	public void testWriteReadCertificate() throws InvalidKeyException, NoSuchAlgorithmException, KeyStoreException,
			CertificateException, OperatorCreationException, IllegalStateException, IOException
	{
		pemFile = newFile();

		CertificateAuthority.registerBouncyCastleProvider();

		CertificateAuthority ca = new CertificateAuthority("DE", null, null, null, null, "Test-CA");
		ca.initialize();

		X509Certificate certificate = ca.getCertificate();

		PemIo.writeX509CertificateToPem(certificate, pemFile);

		X509Certificate readCertificate = PemIo.readX509CertificateFromPem(pemFile);

		assertEquals(certificate, readCertificate);
	}

	@Test
	public void testReadDfnChain() throws Exception
	{
		final String dfnIssuingCa = "DFN-Verein Global Issuing CA";
		final String dfnRootCa = "DFN-Verein Certification Authority 2";
		final String tTelSecRootCa = "T-TeleSec GlobalRoot Class 2";

		KeyStore trustStore = CertificateReader.allFromCer(Paths.get("src/test/resources/dfn_chain.txt"));
		assertNotNull(trustStore);
		List<String> list = Collections.list(trustStore.aliases());
		assertNotNull(list);
		assertEquals(3, list.size());
		assertTrue(trustStore.getCertificate(list.get(0)) instanceof X509Certificate);
		assertTrue(trustStore.getCertificate(list.get(1)) instanceof X509Certificate);
		assertTrue(trustStore.getCertificate(list.get(2)) instanceof X509Certificate);

		X509Certificate cert0 = (X509Certificate) trustStore.getCertificate(list.get(0));
		X509Certificate cert1 = (X509Certificate) trustStore.getCertificate(list.get(1));
		X509Certificate cert2 = (X509Certificate) trustStore.getCertificate(list.get(2));

		boolean dfnIssuingCaFound = Stream.of(cert0, cert1, cert2)
				.filter(cert -> subjectCommonNameEquals(cert, dfnIssuingCa)).count() == 1;
		boolean dfnRootCaFound = Stream.of(cert0, cert1, cert2).filter(cert -> subjectCommonNameEquals(cert, dfnRootCa))
				.count() == 1;
		boolean tTelSecRootCaFound = Stream.of(cert0, cert1, cert2)
				.filter(cert -> subjectCommonNameEquals(cert, tTelSecRootCa)).count() == 1;

		assertTrue(dfnIssuingCaFound);
		assertTrue(dfnRootCaFound);
		assertTrue(tTelSecRootCaFound);
	}

	private boolean subjectCommonNameEquals(X509Certificate cert, String subjectCommonName)
	{
		try
		{
			X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
			RDN cn = x500name.getRDNs(BCStyle.CN)[0];

			return subjectCommonName.equals(IETFUtils.valueToString(cn.getFirst().getValue()));
		}
		catch (CertificateEncodingException e)
		{
			throw new RuntimeException(e);
		}
	}

	private void checkRsaPrivateKeyAndDerivePublicKey(PrivateKey key)
			throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		assertNotNull(key);
		assertEquals("RSA", key.getAlgorithm());
		assertTrue(key instanceof RSAPrivateKey);
		assertEquals(4096, ((RSAPrivateKey) key).getModulus().bitLength());

		assertTrue(key instanceof RSAPrivateCrtKey);
		RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(((RSAPrivateCrtKey) key).getModulus(),
				((RSAPrivateCrtKey) key).getPublicExponent());
		KeyFactory factory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = factory.generatePublic(publicKeySpec);
		assertNotNull(publicKey);
		assertTrue(publicKey instanceof RSAPublicKey);
		assertEquals(4096, ((RSAPublicKey) publicKey).getModulus().bitLength());
	}

	// pkcs8
	// 1.2.840.113549.1.5.13 - Password-Based Encryption Scheme 2 (PBES2)
	// 1.2.840.113549.1.5.12 - Password-Based Key Derivation Function 2 (PBKDF2)
	// 1.2.840.113549.2.9 - HMAC-SHA-256 message authentication scheme
	// 1.2.840.113549.3.7 - Triple Data Encryption Standard (DES) algorithm coupled with a cipher-block chaining mode of
	// operation (szOID_RSA_DES_EDE3_CBC)
	@Test
	public void testReadPkcs83DesEncryptedPrivateKey() throws Exception
	{
		PrivateKey key = PemIo.readPrivateKeyFromPem(provider, Paths.get("src/test/resources/pkcs8_3des.pem"),
				password);

		checkRsaPrivateKeyAndDerivePublicKey(key);
	}

	// pkcs8
	// 1.2.840.113549.1.5.13 - Password-Based Encryption Scheme 2 (PBES2)
	// 1.2.840.113549.1.5.12 - Password-Based Key Derivation Function 2 (PBKDF2)
	// 1.2.840.113549.2.9 - HMAC-SHA-256 message authentication scheme
	// 2.16.840.1.101.3.4.1.2 - Voice encryption 128-bit Advanced Encryption Standard (AES) algorithm with Cipher-Block
	// Chaining (CBC) mode of operation
	@Test
	public void testReadPkcs8Aes128EncryptedPrivateKey() throws Exception
	{
		PrivateKey key = PemIo.readPrivateKeyFromPem(provider, Paths.get("src/test/resources/pkcs8_aes128.pem"),
				password);

		checkRsaPrivateKeyAndDerivePublicKey(key);
	}

	// pkcs8
	// 1.2.840.113549.1.5.13 - Password-Based Encryption Scheme 2 (PBES2)
	// 1.2.840.113549.1.5.12 - Password-Based Key Derivation Function 2 (PBKDF2)
	// 1.2.840.113549.2.9 - HMAC-SHA-256 message authentication scheme
	// 2.16.840.1.101.3.4.1.42 - 256-bit Advanced Encryption Standard (AES) algorithm with Cipher-Block Chaining (CBC)
	// mode of operation
	@Test
	public void testReadPkcs8Aes256EncryptedPrivateKey() throws Exception
	{
		PrivateKey key = PemIo.readPrivateKeyFromPem(provider, Paths.get("src/test/resources/pkcs8_aes256.pem"),
				password);

		checkRsaPrivateKeyAndDerivePublicKey(key);
	}

	// pkcs1
	// 1.2.840.113549.1.1.1 - RSAES-PKCS1-v1_5 encryption scheme
	@Test
	public void testReadPkcs1NotEncryptedPrivateKey() throws Exception
	{
		PrivateKey key = PemIo.readPrivateKeyFromPem(provider, Paths.get("src/test/resources/pkcs1_not_encrypted.pem"),
				null);

		checkRsaPrivateKeyAndDerivePublicKey(key);
	}

	// classic OpenSSL PEM
	// DES-EDE3-CBC
	@Test
	public void testReadOpenSslClassicPem3DesEncryptedPrivateKey() throws Exception
	{
		PrivateKey key = PemIo.readPrivateKeyFromPem(provider, Paths.get("src/test/resources/classic_3des.pem"),
				password);

		checkRsaPrivateKeyAndDerivePublicKey(key);
	}

	// classic OpenSSL PEM
	// AES-128-CBC
	@Test
	public void testReadOpenSslClassicPemAes128EncryptedPrivateKey() throws Exception
	{
		PrivateKey key = PemIo.readPrivateKeyFromPem(provider, Paths.get("src/test/resources/classic_aes128.pem"),
				password);

		checkRsaPrivateKeyAndDerivePublicKey(key);
	}

	// classic OpenSSL PEM
	// AES-256-CBC
	@Test
	public void testReadOpenSslClassicPemAes256EncryptedPrivateKey() throws Exception
	{
		PrivateKey key = PemIo.readPrivateKeyFromPem(provider, Paths.get("src/test/resources/classic_aes256.pem"),
				password);

		checkRsaPrivateKeyAndDerivePublicKey(key);
	}

	// classic OpenSSL PEM
	@Test
	public void testReadOpenSslClassicPemNotEncryptedPrivateKey() throws Exception
	{
		PrivateKey key = PemIo.readPrivateKeyFromPem(provider,
				Paths.get("src/test/resources/classic_not_encrypted.pem"), null);

		checkRsaPrivateKeyAndDerivePublicKey(key);
	}

	@Test
	public void testWrite3DesEncryptedPrivateKeyToPkcs8() throws Exception
	{
		pemFile = newFile();

		KeyPair keyPair = CertificateHelper.createRsaKeyPair4096Bit();
		PemIo.write3DesEncryptedPrivateKeyToPkcs8(provider, pemFile, keyPair.getPrivate(), password);

		PrivateKey readPrivateKey = PemIo.readPrivateKeyFromPem(provider, pemFile, password);
		checkRsaPrivateKeyAndDerivePublicKey(readPrivateKey);

		assertEquals(keyPair.getPrivate(), readPrivateKey);
	}

	@Test
	public void testWriteAes128EncryptedPrivateKeyToPkcs8() throws Exception
	{
		pemFile = newFile();

		KeyPair keyPair = CertificateHelper.createRsaKeyPair4096Bit();
		PemIo.writeAes128EncryptedPrivateKeyToPkcs8(provider, pemFile, keyPair.getPrivate(), password);

		PrivateKey readPrivateKey = PemIo.readPrivateKeyFromPem(provider, pemFile, password);
		checkRsaPrivateKeyAndDerivePublicKey(readPrivateKey);

		assertEquals(keyPair.getPrivate(), readPrivateKey);
	}

	@Test
	public void testWriteAes256EncryptedPrivateKeyToPkcs8() throws Exception
	{
		pemFile = newFile();

		KeyPair keyPair = CertificateHelper.createRsaKeyPair4096Bit();
		PemIo.writeAes256EncryptedPrivateKeyToPkcs8(provider, pemFile, keyPair.getPrivate(), password);

		PrivateKey readPrivateKey = PemIo.readPrivateKeyFromPem(provider, pemFile, password);
		checkRsaPrivateKeyAndDerivePublicKey(readPrivateKey);

		assertEquals(keyPair.getPrivate(), readPrivateKey);
	}

	@Test
	public void testWriteNotEncryptedPrivateKeyToPkcs8() throws Exception
	{
		pemFile = newFile();

		KeyPair keyPair = CertificateHelper.createRsaKeyPair4096Bit();
		PemIo.writeNotEncryptedPrivateKeyToPkcs8(provider, pemFile, keyPair.getPrivate());

		PrivateKey readPrivateKey = PemIo.readPrivateKeyFromPem(provider, pemFile);
		checkRsaPrivateKeyAndDerivePublicKey(readPrivateKey);

		assertEquals(keyPair.getPrivate(), readPrivateKey);
	}

	@Test
	public void testWrite3DesEncryptedPrivateKeyToOpenSslClassicPem() throws Exception
	{
		pemFile = newFile();

		KeyPair keyPair = CertificateHelper.createRsaKeyPair4096Bit();
		PemIo.write3DesEncryptedPrivateKeyToOpenSslClassicPem(provider, pemFile, keyPair.getPrivate(), password);

		PrivateKey readPrivateKey = PemIo.readPrivateKeyFromPem(provider, pemFile, password);
		checkRsaPrivateKeyAndDerivePublicKey(readPrivateKey);

		assertEquals(keyPair.getPrivate(), readPrivateKey);
	}

	@Test
	public void testWriteAes128EncryptedPrivateKeyToOpenSslClassicPem() throws Exception
	{
		pemFile = newFile();

		KeyPair keyPair = CertificateHelper.createRsaKeyPair4096Bit();
		PemIo.writeAes128EncryptedPrivateKeyToOpenSslClassicPem(provider, pemFile, keyPair.getPrivate(), password);

		PrivateKey readPrivateKey = PemIo.readPrivateKeyFromPem(provider, pemFile, password);
		checkRsaPrivateKeyAndDerivePublicKey(readPrivateKey);

		assertEquals(keyPair.getPrivate(), readPrivateKey);
	}

	@Test
	public void testWriteAes256EncryptedPrivateKeyToOpenSslClassicPem() throws Exception
	{
		pemFile = newFile();

		KeyPair keyPair = CertificateHelper.createRsaKeyPair4096Bit();
		PemIo.writeAes256EncryptedPrivateKeyToOpenSslClassicPem(provider, pemFile, keyPair.getPrivate(), password);

		PrivateKey readPrivateKey = PemIo.readPrivateKeyFromPem(provider, pemFile, password);
		checkRsaPrivateKeyAndDerivePublicKey(readPrivateKey);

		assertEquals(keyPair.getPrivate(), readPrivateKey);
	}

	@Test
	public void testWriteNotEncryptedPrivateKeyToOpenSslClassicPem() throws Exception
	{
		pemFile = newFile();

		KeyPair keyPair = CertificateHelper.createRsaKeyPair4096Bit();
		PemIo.writeNotEncryptedPrivateKeyToOpenSslClassicPem(provider, pemFile, keyPair.getPrivate());

		PrivateKey readPrivateKey = PemIo.readPrivateKeyFromPem(provider, pemFile);
		checkRsaPrivateKeyAndDerivePublicKey(readPrivateKey);

		assertEquals(keyPair.getPrivate(), readPrivateKey);
	}
}

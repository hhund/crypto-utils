/**
 * 
 */
package de.rwh.utils.crypto;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.rwh.utils.crypto.io.CertificateReader;
import de.rwh.utils.crypto.io.CertificateWriter;

/**
 * @author hhund
 * 
 */
public class IoTest
{
	private static final String CA_ALIAS = "PS-CA";

	private static final String SERVER_CERTIFICATE_PASSWORD = "ServerPassword";
	private static final String SERVER_CERTIFICATE_ALIAS = "ServerAlias";

	private static final String CLIENT_CERTIFICATE_PASSWORD = "ClientPassword";
	private static final String CLIENT_CERTIFICATE_ALIAS = "ClientAlias";

	private Path testRoot = Paths.get("target/io-test");
	private List<Path> createdFiles = new ArrayList<>();

	private KeyStore trustStore;
	private KeyStore serverKeyStore;
	private KeyStore clientKeyStore;

	@Before
	public void before() throws InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException,
			OperatorCreationException, IllegalStateException, IOException, InvalidKeySpecException
	{
		Security.addProvider(new BouncyCastleProvider());

		CertificationAuthority ca = new CertificationAuthority("DE", "Baden-Wuerttemberg", "Heilbronn",
				"Hochschule Heilbronn", "Medizinische Informatik", CA_ALIAS);
		ca.initialize();

		X509Certificate psCaCertificate = ca.getCertificate();
		trustStore = CertificateHelper.toCertificateStore(CA_ALIAS, psCaCertificate);

		KeyPair serverKeyPair = CertificationRequestBuilder.createRsaKeyPair();
		X500Name serverSubject = CertificationRequestBuilder.createSubject("DE", "Baden Wuerttemberg", "Heilbronn",
				"Hochschule Heilbronn", "Medizinische Informatik", "localhost");
		JcaPKCS10CertificationRequest serverCR = CertificationRequestBuilder.createCertificationRequest(serverSubject,
				serverKeyPair, "server@localhost");
		X509Certificate serverCertificate = ca.signWebServerCertificate(serverCR);

		serverKeyStore = CertificateHelper.toPkcs12KeyStore(serverKeyPair.getPrivate(), new Certificate[] {
				serverCertificate, psCaCertificate }, SERVER_CERTIFICATE_ALIAS, SERVER_CERTIFICATE_PASSWORD);

		X500Name clientSubject = CertificationRequestBuilder.createSubject("DE", "Baden Wuerttemberg", "Heilbronn",
				"Hochschule Heilbronn", "Medizinische Informatik", "User");
		KeyPair clientKeyPair = CertificationRequestBuilder.createRsaKeyPair();
		JcaPKCS10CertificationRequest clientCR = CertificationRequestBuilder.createCertificationRequest(clientSubject,
				clientKeyPair, "hauke.hund@hs-heilbronn.de");
		X509Certificate clientCertificate = ca.signWebClientCertificate(clientCR);

		clientKeyStore = CertificateHelper.toPkcs12KeyStore(clientKeyPair.getPrivate(), new Certificate[] {
				clientCertificate, psCaCertificate }, CLIENT_CERTIFICATE_ALIAS, CLIENT_CERTIFICATE_PASSWORD);

		Files.createDirectory(testRoot);
	}

	@After
	public void after() throws IOException
	{
		for (Path file : createdFiles)
			Files.deleteIfExists(file);

		Files.deleteIfExists(testRoot);
	}

	@Test
	public void readWriteTest() throws Exception
	{
		Path trustStoreFile = testRoot.resolve("ca.cer");
		createdFiles.add(trustStoreFile);

		CertificateWriter.toCer(trustStoreFile, trustStore, CA_ALIAS);

		KeyStore readKeyStore = CertificateReader.fromCer(trustStoreFile, CA_ALIAS);

		Certificate readCaCertificate = readKeyStore.getCertificate(CA_ALIAS);
		assertNotNull(readCaCertificate);

		assertEquals(trustStore.getCertificate(CA_ALIAS), readCaCertificate);

		Path serverKeyStoreFile = testRoot.resolve("server-key.p12");
		createdFiles.add(serverKeyStoreFile);
		testPkcs12ReadWrite(serverKeyStoreFile, serverKeyStore, SERVER_CERTIFICATE_PASSWORD, SERVER_CERTIFICATE_ALIAS);

		Path clientKeyStoreFile = testRoot.resolve("client-key.p12");
		createdFiles.add(clientKeyStoreFile);
		testPkcs12ReadWrite(clientKeyStoreFile, clientKeyStore, CLIENT_CERTIFICATE_PASSWORD, CLIENT_CERTIFICATE_ALIAS);
	}

	private void testPkcs12ReadWrite(Path keyStoreFile, KeyStore keyStore, String certificatePassword,
			String certificateAlias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		CertificateWriter.toPkcs12(keyStoreFile, keyStore, certificatePassword);

		KeyStore readServerKeyStore = CertificateReader.fromPkcs12(keyStoreFile, certificatePassword);
		Key readServerKey = readServerKeyStore.getKey(certificateAlias, certificatePassword.toCharArray());
		Certificate[] readServerCertificateChain = readServerKeyStore.getCertificateChain(certificateAlias);

		assertNotNull(readServerKey);
		assertNotNull(readServerCertificateChain);
		assertEquals(2, readServerCertificateChain.length);
		assertEquals(2, keyStore.getCertificateChain(certificateAlias).length);
		assertEquals(keyStore.getCertificateChain(certificateAlias)[0], readServerCertificateChain[0]);
		assertEquals(keyStore.getCertificateChain(certificateAlias)[1], readServerCertificateChain[1]);
	}
}

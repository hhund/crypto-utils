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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.rwh.utils.crypto.io.CertificateReader;
import de.rwh.utils.crypto.io.CertificateWriter;

public class IoTest
{
	private static final Logger logger = LoggerFactory.getLogger(IoTest.class);

	private static final String CA_ALIAS = "CA";

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

		CertificateAuthority ca = new CertificateAuthority("DE", "Baden-Wuerttemberg", "Heilbronn",
				"Hochschule Heilbronn", "Medizinische Informatik", CA_ALIAS);
		ca.initialize();

		X509Certificate caCertificate = ca.getCertificate();
		logger.debug("CA Certificate: " + caCertificate.toString());
		trustStore = CertificateHelper.toCertificateStore(CA_ALIAS, caCertificate);

		KeyPair serverKeyPair = CertificateHelper.createKeyPair(CertificateHelper.DEFAULT_KEY_ALGORITHM, 2048);
		X500Name serverSubject = CertificationRequestBuilder.createSubject("DE", "Baden Wuerttemberg", "Heilbronn",
				"Hochschule Heilbronn", "Medizinische Informatik", "localhost");
		JcaPKCS10CertificationRequest serverCR = CertificationRequestBuilder
				.createServerCertificationRequest(serverSubject, serverKeyPair, "server@localhost");
		X509Certificate serverCertificate = ca.signWebServerCertificate(serverCR);
		logger.debug("Server Certificate: " + serverCertificate.toString());

		serverKeyStore = CertificateHelper.toPkcs12KeyStore(serverKeyPair.getPrivate(),
				new Certificate[] { serverCertificate, caCertificate }, SERVER_CERTIFICATE_ALIAS,
				SERVER_CERTIFICATE_PASSWORD);

		X500Name clientSubject = CertificationRequestBuilder.createSubject("DE", "Baden Wuerttemberg", "Heilbronn",
				"Hochschule Heilbronn", "Medizinische Informatik", "User");
		KeyPair clientKeyPair = CertificateHelper.createKeyPair(CertificateHelper.DEFAULT_KEY_ALGORITHM, 2048);
		JcaPKCS10CertificationRequest clientCR = CertificationRequestBuilder
				.createClientCertificationRequest(clientSubject, clientKeyPair, "hauke.hund@hs-heilbronn.de");
		X509Certificate clientCertificate = ca.signWebClientCertificate(clientCR);
		logger.debug("Client Certificate: " + clientCertificate.toString());

		clientKeyStore = CertificateHelper.toPkcs12KeyStore(clientKeyPair.getPrivate(),
				new Certificate[] { clientCertificate, caCertificate }, CLIENT_CERTIFICATE_ALIAS,
				CLIENT_CERTIFICATE_PASSWORD);

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
			String certificateAlias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException,
					CertificateException, IOException
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

	@Test
	public void testCertificateHelperListCertificateSubjectNames() throws Exception
	{
		List<String> trustStoreList = CertificateHelper.listCertificateSubjectNames(trustStore);
		List<String> clientKeyStoreList = CertificateHelper.listCertificateSubjectNames(clientKeyStore);
		List<String> serverKeyStoreList = CertificateHelper.listCertificateSubjectNames(serverKeyStore);

		assertEquals(1, trustStoreList.size());
		assertEquals(1, clientKeyStoreList.size());
		assertEquals(1, serverKeyStoreList.size());

		assertEquals(
				"CN=CA, OU=Medizinische Informatik, O=Hochschule Heilbronn, L=Heilbronn, ST=Baden-Wuerttemberg, C=DE",
				trustStoreList.get(0));
		assertEquals(
				"CN=User, OU=Medizinische Informatik, O=Hochschule Heilbronn, L=Heilbronn, ST=Baden Wuerttemberg, C=DE",
				clientKeyStoreList.get(0));
		assertEquals(
				"CN=localhost, OU=Medizinische Informatik, O=Hochschule Heilbronn, L=Heilbronn, ST=Baden Wuerttemberg, C=DE",
				serverKeyStoreList.get(0));
	}
}

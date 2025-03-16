package de.hsheilbronn.mi.utils.crypto.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest.CertificationRequestAndPrivateKey;
import de.hsheilbronn.mi.utils.crypto.keystore.KeyStoreCreator;

public class CertificateValidatorTest
{
	private static final Logger logger = LoggerFactory.getLogger(CertificateValidatorTest.class);

	private static final CertificateAuthority rootCa = CertificateAuthority
			.builderSha384EcdsaSecp384r1("DE", null, null, null, null, "JUnit Root CA").build();
	private static final CertificateAuthority issuingCa;
	static
	{
		CertificationRequestAndPrivateKey issuingCaRequest = CertificationRequest
				.builder(rootCa, "DE", null, null, null, null, "JUnit Issuing CA").generateKeyPair().signRequest();
		X509Certificate issuingCaCertificate = rootCa.signClientServerIssuingCaCertificate(issuingCaRequest);

		issuingCa = CertificateAuthority.existingCa(issuingCaCertificate, issuingCaRequest.getPrivateKey());
	}

	private static final X509Certificate clientCertificate;
	static
	{
		CertificationRequestAndPrivateKey request = CertificationRequest
				.builder(issuingCa, "DE", null, null, null, null, "JUnit Test Client").generateKeyPair().signRequest();
		clientCertificate = issuingCa.signClientCertificate(request);
	}

	private static final X509Certificate serverCertificate;
	static
	{
		CertificationRequestAndPrivateKey request = CertificationRequest
				.builder(issuingCa, "DE", null, null, null, null, "junit.test.server").generateKeyPair().signRequest();
		serverCertificate = issuingCa.signServerCertificate(request);
	}

	@Test
	void vaildateClientCertificate() throws Exception
	{
		KeyStore rootCaTrustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa.getCertificate());
		CertificateValidator.vaildateClientCertificate(rootCaTrustStore,
				new X509Certificate[] { clientCertificate, issuingCa.getCertificate() });

		KeyStore issuingCaTrustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa.getCertificate(),
				issuingCa.getCertificate());
		CertificateValidator.vaildateClientCertificate(issuingCaTrustStore,
				new X509Certificate[] { clientCertificate });

		assertFalse(CertificateValidator.isCertificateExpired(clientCertificate));
		assertTrue(CertificateValidator.isClientCertificate(clientCertificate));
		assertFalse(CertificateValidator.isServerCertificate(clientCertificate));
	}

	@Test
	void vaildateServerCertificate() throws Exception
	{
		KeyStore rootCaTrustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa.getCertificate());
		CertificateValidator.vaildateServerCertificate(rootCaTrustStore,
				new X509Certificate[] { serverCertificate, issuingCa.getCertificate() });

		KeyStore issuingCaTrustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa.getCertificate(),
				issuingCa.getCertificate());
		CertificateValidator.vaildateServerCertificate(issuingCaTrustStore,
				new X509Certificate[] { serverCertificate });

		assertFalse(CertificateValidator.isCertificateExpired(serverCertificate));
		assertFalse(CertificateValidator.isClientCertificate(serverCertificate));
		assertTrue(CertificateValidator.isServerCertificate(serverCertificate));
	}

	@Test
	void vaildateClientCertificateExpired() throws Exception
	{
		CertificationRequestAndPrivateKey request = CertificationRequest
				.builder(rootCa, "DE", null, null, null, null, "JUnit Test Client").generateKeyPair().signRequest();
		X509Certificate expiredClientCertificate = issuingCa.signClientCertificate(request, Duration.ZERO);

		Thread.sleep(Duration.ofMillis(10));

		assertTrue(CertificateValidator.isCertificateExpired(expiredClientCertificate));

		KeyStore trustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa.getCertificate(),
				issuingCa.getCertificate());

		CertificateException ex = assertThrows(CertificateException.class, () -> CertificateValidator
				.vaildateClientCertificate(trustStore, new X509Certificate[] { expiredClientCertificate }));

		assertEquals(
				"PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed",
				ex.getMessage());
	}

	@Test
	void vaildateServerCertificateExpired() throws Exception
	{
		CertificationRequestAndPrivateKey request = CertificationRequest
				.builder(rootCa, "DE", null, null, null, null, "junit.test.server").generateKeyPair().signRequest();
		X509Certificate expiredServerCertificate = issuingCa.signServerCertificate(request, Duration.ZERO);

		Thread.sleep(Duration.ofMillis(10));

		assertTrue(CertificateValidator.isCertificateExpired(expiredServerCertificate));

		KeyStore trustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa.getCertificate(),
				issuingCa.getCertificate());

		CertificateException ex = assertThrows(CertificateException.class, () -> CertificateValidator
				.vaildateClientCertificate(trustStore, new X509Certificate[] { expiredServerCertificate }));

		assertEquals(
				"PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed",
				ex.getMessage());
	}

	@Test
	void vaildateClientCertificateOtherCa() throws Exception
	{
		CertificateAuthority rootCa2 = CertificateAuthority
				.builderEd25519("DE", null, null, null, null, "JUnit Root CA 2").build();

		KeyStore trustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa2.getCertificate());

		assertFalse(CertificateValidator.isCertificateExpired(clientCertificate));

		CertificateException ex = assertThrows(CertificateException.class,
				() -> CertificateValidator.vaildateClientCertificate(trustStore,
						new X509Certificate[] { clientCertificate, issuingCa.getCertificate() }));

		assertEquals(
				"PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target",
				ex.getMessage());
	}

	@Test
	void vaildateServerCertificateOtherCa() throws Exception
	{
		CertificateAuthority rootCa2 = CertificateAuthority
				.builderEd25519("DE", null, null, null, null, "JUnit Root CA 2").build();

		KeyStore trustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa2.getCertificate());

		assertFalse(CertificateValidator.isCertificateExpired(serverCertificate));

		CertificateException ex = assertThrows(CertificateException.class,
				() -> CertificateValidator.vaildateServerCertificate(trustStore,
						new X509Certificate[] { serverCertificate, issuingCa.getCertificate() }));

		assertEquals(
				"PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target",
				ex.getMessage());
	}

	@Test
	void vaildateClientCertificateWithServerCertificate() throws Exception
	{
		KeyStore trustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa.getCertificate());

		assertFalse(CertificateValidator.isCertificateExpired(serverCertificate));

		CertificateException ex = assertThrows(CertificateException.class,
				() -> CertificateValidator.vaildateClientCertificate(trustStore,
						new X509Certificate[] { serverCertificate, issuingCa.getCertificate() }));

		assertEquals("Extended key usage does not permit use for TLS client authentication", ex.getMessage());
	}

	@Test
	void vaildateServerCertificateWithClientCertificate() throws Exception
	{
		KeyStore trustStore = KeyStoreCreator.jksForTrustedCertificates(rootCa.getCertificate());

		assertFalse(CertificateValidator.isCertificateExpired(clientCertificate));

		CertificateException ex = assertThrows(CertificateException.class,
				() -> CertificateValidator.vaildateServerCertificate(trustStore,
						new X509Certificate[] { clientCertificate, issuingCa.getCertificate() }));

		assertEquals("Extended key usage does not permit use for TLS server authentication", ex.getMessage());
	}

	@Test
	void scheduleExpiryWarning() throws Exception
	{
		CertificationRequestAndPrivateKey request = CertificationRequest
				.builder(rootCa, "DE", null, null, null, null, "junit.test.server").generateKeyPair().signRequest();
		X509Certificate serverCertificate = issuingCa.signServerCertificate(request, Duration.ofDays(10));

		ScheduledFuture<Void> f = CertificateValidator.scheduleExpiryWarning(Executors.newScheduledThreadPool(1),
				Duration.ofDays(20), serverCertificate, CertificateValidator.loggerConsumer(logger));

		f.get(1, TimeUnit.MINUTES);
	}
}

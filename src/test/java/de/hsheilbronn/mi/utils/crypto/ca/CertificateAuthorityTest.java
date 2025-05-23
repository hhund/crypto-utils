package de.hsheilbronn.mi.utils.crypto.ca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority.RevocationEntry;
import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority.RevocationReason;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest.CertificationRequestAndPrivateKey;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest.CertificationRequestBuilder;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest.CertificationRequestBuilderKeyPair;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest.CertificationRequestBuilderKeyPairGenerator;
import de.hsheilbronn.mi.utils.crypto.cert.CertificateFormatter;

public class CertificateAuthorityTest
{
	private static final Logger logger = LoggerFactory.getLogger(CertificateAuthorityTest.class);

	@Test
	public void testRsa3072() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderSha256Rsa3072("DE", null, null, null, null, "RSA3072-CA")
				.setValidityPeriod(CertificateAuthority.TEN_YEARS).build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("RSA3072-CA certificate:\n{}", CertificateFormatter.toOpenSslStyleText(ca.getCertificate()));

		X509Certificate clientCert = testSignClientCertificate(ca);
		X509Certificate smimeCert = testSignSmimeCertificate(ca);
		X509Certificate serverCert = testSignServerCertificate(ca);

		testGenerateEmptyCrl(ca);
		testGenerateCrl(ca, clientCert, smimeCert, serverCert);

		testInitCaFromExisting(ca.getCertificate(), ca.getKeyPair().getPrivate());
	}

	@Test
	public void testRsa4096() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderSha512Rsa4096("DE", null, null, null, null, "RSA4096-CA")
				.setValidityPeriod(CertificateAuthority.TEN_YEARS).build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("RSA4096-CA certificate:\n{}", CertificateFormatter.toOpenSslStyleText(ca.getCertificate()));

		X509Certificate clientCert = testSignClientCertificate(ca);
		X509Certificate smimeCert = testSignSmimeCertificate(ca);
		X509Certificate serverCert = testSignServerCertificate(ca);

		testGenerateEmptyCrl(ca);
		testGenerateCrl(ca, clientCert, smimeCert, serverCert);

		testInitCaFromExisting(ca.getCertificate(), ca.getKeyPair().getPrivate());
	}

	@Test
	public void testSecp384r1() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority
				.builderSha384EcdsaSecp384r1("DE", null, null, null, null, "secp384r1-CA")
				.setValidityPeriod(CertificateAuthority.TEN_YEARS).build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("secp384r1-CA certificate:\n{}", CertificateFormatter.toOpenSslStyleText(ca.getCertificate()));

		X509Certificate clientCert = testSignClientCertificate(ca);
		X509Certificate smimeCert = testSignSmimeCertificate(ca);
		X509Certificate serverCert = testSignServerCertificate(ca);

		testGenerateEmptyCrl(ca);
		testGenerateCrl(ca, clientCert, smimeCert, serverCert);

		testInitCaFromExisting(ca.getCertificate(), ca.getKeyPair().getPrivate());
	}

	@Test
	public void testSecp521r1() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority
				.builderSha512EcdsaSecp521r1("DE", null, null, null, null, "secp521r1-CA")
				.setValidityPeriod(CertificateAuthority.TEN_YEARS).build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("secp521r1-CA certificate:\n{}", CertificateFormatter.toOpenSslStyleText(ca.getCertificate()));

		X509Certificate clientCert = testSignClientCertificate(ca);
		X509Certificate smimeCert = testSignSmimeCertificate(ca);
		X509Certificate serverCert = testSignServerCertificate(ca);

		testGenerateEmptyCrl(ca);
		testGenerateCrl(ca, clientCert, smimeCert, serverCert);

		testInitCaFromExisting(ca.getCertificate(), ca.getKeyPair().getPrivate());
	}

	@Test
	public void testSecp521r1WithIssuingCa() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority
				.builderSha512EcdsaSecp521r1("DE", null, null, null, null, "secp521r1-CA")
				.setValidityPeriod(CertificateAuthority.TEN_YEARS).build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("secp521r1-CA certificate:\n{}", CertificateFormatter.toOpenSslStyleText(ca.getCertificate()));

		CertificationRequestBuilderKeyPairGenerator clientServerIssuingCaRequestBuilderForKeyGenerator = CertificationRequest
				.builder(ca, "DE", null, null, null, null, "secp521r1-Client-Server-Issuing-CA");
		assertNotNull(clientServerIssuingCaRequestBuilderForKeyGenerator);

		CertificationRequestBuilder clientServerIssuingCaRequestBuilder = clientServerIssuingCaRequestBuilderForKeyGenerator
				.generateKeyPair();
		assertNotNull(clientServerIssuingCaRequestBuilder);
		assertNotNull(clientServerIssuingCaRequestBuilder.getKeyPair());

		CertificationRequestAndPrivateKey clientServerIssuingCaRequest = clientServerIssuingCaRequestBuilder.build();
		checkRequest(clientServerIssuingCaRequest);

		CertificationRequestBuilderKeyPairGenerator clientSmimeIssuingCaRequestBuilderForKeyGenerator = CertificationRequest
				.builder(ca, "DE", null, null, null, null, "secp521r1-Client-Server-Issuing-CA");
		assertNotNull(clientSmimeIssuingCaRequestBuilderForKeyGenerator);

		CertificationRequestBuilder clientSmimeIssuingCaRequestBuilder = clientSmimeIssuingCaRequestBuilderForKeyGenerator
				.generateKeyPair();
		assertNotNull(clientSmimeIssuingCaRequestBuilder);
		assertNotNull(clientSmimeIssuingCaRequestBuilder.getKeyPair());

		CertificationRequestAndPrivateKey clientSmimeIssuingCaRequest = clientSmimeIssuingCaRequestBuilder.build();
		checkRequest(clientSmimeIssuingCaRequest);

		X509Certificate clientServerIssuingCaCertificate = ca
				.signClientServerIssuingCaCertificate(clientSmimeIssuingCaRequest);
		assertNotNull(clientServerIssuingCaCertificate);

		X509Certificate clientSmimeIssuingCaCertificate = ca
				.signClientSmimeIssuingCaCertificate(clientSmimeIssuingCaRequest);
		assertNotNull(clientSmimeIssuingCaCertificate);

		CertificateAuthority clientServerIssuingCa = testInitCaFromExisting(clientServerIssuingCaCertificate,
				clientServerIssuingCaRequest.getPrivateKey());
		logger.debug("secp521r1-Client-Server-Issuing-CA certificate:\n{}",
				CertificateFormatter.toOpenSslStyleText(clientServerIssuingCa.getCertificate()));
		CertificateAuthority clientSmimeIssuingCa = testInitCaFromExisting(clientSmimeIssuingCaCertificate,
				clientSmimeIssuingCaRequest.getPrivateKey());
		logger.debug("secp521r1-Client-Server-Issuing-CA certificate:\n{}",
				CertificateFormatter.toOpenSslStyleText(clientSmimeIssuingCa.getCertificate()));

		X509Certificate clientCert = testSignClientCertificate(clientServerIssuingCa);
		X509Certificate smimeCert = testSignSmimeCertificate(clientSmimeIssuingCa);
		X509Certificate serverCert = testSignServerCertificate(clientServerIssuingCa);

		testGenerateEmptyCrl(clientServerIssuingCa);
		testGenerateCrl(clientServerIssuingCa, clientCert, smimeCert, serverCert);

		testInitCaFromExisting(clientServerIssuingCa.getCertificate(), clientServerIssuingCa.getKeyPair().getPrivate());
	}

	private void checkRequest(CertificationRequestAndPrivateKey request)
	{
		assertNotNull(request);
		assertNotNull(request.getPrivateKey());
		assertNotNull(request.getPublicKey());
		assertNotNull(request.getRequest());
		assertNotNull(request.getSubject());
	}

	@Test
	public void testEd25519() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderEd25519("DE", null, null, null, null, "ed25519-CA")
				.setValidityPeriod(CertificateAuthority.TEN_YEARS).build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("ed25519-CA certificate:\n{}", CertificateFormatter.toOpenSslStyleText(ca.getCertificate()));

		X509Certificate clientCert = testSignClientCertificate(ca);
		X509Certificate smimeCert = testSignSmimeCertificate(ca);
		X509Certificate serverCert = testSignServerCertificate(ca);

		testGenerateEmptyCrl(ca);
		testGenerateCrl(ca, clientCert, smimeCert, serverCert);

		testInitCaFromExisting(ca.getCertificate(), ca.getKeyPair().getPrivate());
	}

	@Test
	public void testEd448() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderEd448("DE", null, null, null, null, "ed448-CA")
				.setValidityPeriod(CertificateAuthority.TEN_YEARS).build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("ed448-CA certificate:\n{}", CertificateFormatter.toOpenSslStyleText(ca.getCertificate()));

		X509Certificate clientCert = testSignClientCertificate(ca);
		X509Certificate smimeCert = testSignSmimeCertificate(ca);
		X509Certificate serverCert = testSignServerCertificate(ca);

		testGenerateEmptyCrl(ca);
		testGenerateCrl(ca, clientCert, smimeCert, serverCert);

		testInitCaFromExisting(ca.getCertificate(), ca.getKeyPair().getPrivate());
	}

	private X509Certificate testSignClientCertificate(CertificateAuthority ca)
	{
		CertificationRequestBuilderKeyPairGenerator builderKeyPairGenerator = CertificationRequest.builder(ca, "DE",
				null, null, null, null, "client");
		assertNotNull(builderKeyPairGenerator);

		CertificationRequestBuilder builder = builderKeyPairGenerator.generateKeyPair();
		assertNotNull(builder);
		assertNotNull(builder.getKeyPair());

		builder.setEmail("email@test.com");

		CertificationRequestAndPrivateKey request = builder.build();
		checkRequest(request);

		X509Certificate certificate = ca.signClientCertificate(request);
		assertNotNull(certificate);

		logger.debug("Client certificate:\n{}", CertificateFormatter.toOpenSslStyleText(certificate));

		return certificate;
	}

	private X509Certificate testSignSmimeCertificate(CertificateAuthority ca)
	{
		CertificationRequestBuilderKeyPair builderKeyPair = CertificationRequest.builder(ca.getContentSignerBuilder(),
				CertificateAuthority.createName("DE", null, null, null, null, "client"));
		assertNotNull(builderKeyPair);

		KeyPairGenerator generator = ca.getKeyPairGeneratorFactory().initialize();
		assertNotNull(generator);
		KeyPair keyPair = generator.generateKeyPair();
		assertNotNull(keyPair);

		CertificationRequestBuilder builder = builderKeyPair.forKeyPair(keyPair);
		assertNotNull(builder);
		assertNotNull(builder.getKeyPair());
		assertEquals(keyPair, builder.getKeyPair());

		builder.setEmail("email@test.com");

		CertificationRequestAndPrivateKey request = builder.build();
		checkRequest(request);

		X509Certificate certificate = ca.signSmimeCertificate(request);
		assertNotNull(certificate);

		logger.debug("S/MIME certificate:\n{}", CertificateFormatter.toOpenSslStyleText(certificate));

		return certificate;
	}

	private X509Certificate testSignServerCertificate(CertificateAuthority ca)
	{
		CertificationRequestBuilderKeyPairGenerator builderKeyPairGenerator = CertificationRequest.builder(ca, "DE",
				null, null, null, null, "server");
		assertNotNull(builderKeyPairGenerator);

		CertificationRequestBuilder builder = builderKeyPairGenerator.generateKeyPair();
		assertNotNull(builder);
		assertNotNull(builder.getKeyPair());

		builder.setEmail("email@test.com");
		builder.addDnsName("localhost");

		CertificationRequestAndPrivateKey request = builder.build();
		checkRequest(request);
		List<GeneralName> names = CertificateAuthority.getSubjectAlternativeNames(request.getRequest());
		assertNotNull(names);
		assertEquals(3, names.size());

		X509Certificate certificate = ca.signServerCertificate(request);
		assertNotNull(certificate);

		logger.debug("Server certificate:\n{}", CertificateFormatter.toOpenSslStyleText(certificate));

		return certificate;
	}

	private void testGenerateEmptyCrl(CertificateAuthority ca)
	{
		X509CRL crl = ca.createEmptyRevocationList();
		assertNotNull(crl);

		logger.debug("CRL:\n{}", crl.toString());
	}

	private void testGenerateCrl(CertificateAuthority ca, X509Certificate... certs)
	{
		X509CRL crl = ca.createRevocationList(Stream.of(certs)
				.map(c -> new RevocationEntry(c, LocalDateTime.now(), RevocationReason.PRIVILEGE_WITHDRAWN)).toList());
		assertNotNull(crl);

		logger.debug("CRL:\n{}", crl.toString());
	}

	private CertificateAuthority testInitCaFromExisting(X509Certificate certificate, PrivateKey privateKey)
	{
		CertificateAuthority ca = CertificateAuthority.existingCa(certificate, privateKey);
		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		return ca;
	}
}

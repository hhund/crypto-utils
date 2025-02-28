package de.hsheilbronn.mi.utils.crypto.ca;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority.RevocationEntry;
import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority.RevocationReason;

public class CertificateAuthorityTest
{
	private static final Logger logger = LoggerFactory.getLogger(CertificateAuthorityTest.class);

	@Test
	public void testRsa3072() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderSha256Rsa3072()
				.newCa("DE", null, null, null, null, "RSA3072-CA").validityPeriod(CertificateAuthority.TEN_YEARS)
				.build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("RSA3072-CA certificate:\n{}", ca.getCertificate().toString());

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
		CertificateAuthority ca = CertificateAuthority.builderSha512Rsa4096()
				.newCa("DE", null, null, null, null, "RSA4096-CA").validityPeriod(CertificateAuthority.TEN_YEARS)
				.build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("RSA4096-CA certificate:\n{}", ca.getCertificate().toString());

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
		CertificateAuthority ca = CertificateAuthority.builderSha384EcdsaSecp384r1()
				.newCa("DE", null, null, null, null, "secp384r1-CA").validityPeriod(CertificateAuthority.TEN_YEARS)
				.build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("secp384r1-CA certificate:\n{}", ca.getCertificate().toString());

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
		CertificateAuthority ca = CertificateAuthority.builderSha512EcdsaSecp521r1()
				.newCa("DE", null, null, null, null, "secp521r1-CA").validityPeriod(CertificateAuthority.TEN_YEARS)
				.build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("secp521r1-CA certificate:\n{}", ca.getCertificate().toString());

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
		CertificateAuthority ca = CertificateAuthority.builderSha512EcdsaSecp521r1()
				.newCa("DE", null, null, null, null, "secp521r1-CA").validityPeriod(CertificateAuthority.TEN_YEARS)
				.build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("secp521r1-CA certificate:\n{}", ca.getCertificate().toString());

		CertificationRequestBuilder builder = ca.createCertificationRequestBuilder();
		assertNotNull(builder);

		KeyPair clienServerIssuingCaKeyPair = builder.getKeyPairGenerator().generateKeyPair();
		assertNotNull(clienServerIssuingCaKeyPair);
		X500Name clientServerIssuingCaSubject = builder.createName("DE", null, null, null, null,
				"secp521r1-Client-Server-Issuing-CA");
		assertNotNull(clientServerIssuingCaSubject);
		JcaPKCS10CertificationRequest clientServerIssuingCaRequest = builder
				.createCertificationRequest(clienServerIssuingCaKeyPair, clientServerIssuingCaSubject);
		assertNotNull(clientServerIssuingCaRequest);

		KeyPair clienSmimeIssuingCaKeyPair = builder.getKeyPairGenerator().generateKeyPair();
		assertNotNull(clienSmimeIssuingCaKeyPair);
		X500Name clientSmimeIssuingCaSubject = builder.createName("DE", null, null, null, null,
				"secp521r1-Client-S/MIME-Issuing-CA");
		assertNotNull(clientSmimeIssuingCaSubject);
		JcaPKCS10CertificationRequest clientSmimeIssuingCaRequest = builder
				.createCertificationRequest(clienSmimeIssuingCaKeyPair, clientSmimeIssuingCaSubject);
		assertNotNull(clientSmimeIssuingCaRequest);

		X509Certificate clientServerIssuingCaCertificate = ca
				.signClientServerIssuingCaCertificate(clientServerIssuingCaRequest);
		X509Certificate clientSmimeIssuingCaCertificate = ca
				.signClientSmimeIssuingCaCertificate(clientSmimeIssuingCaRequest);

		CertificateAuthority clientServerIssuingCa = testInitCaFromExisting(clientServerIssuingCaCertificate,
				clienServerIssuingCaKeyPair.getPrivate());
		logger.debug("secp521r1-Client-Server-Issuing-CA certificate:\n{}",
				clientServerIssuingCa.getCertificate().toString());
		CertificateAuthority clientSmimeIssuingCa = testInitCaFromExisting(clientSmimeIssuingCaCertificate,
				clienSmimeIssuingCaKeyPair.getPrivate());
		logger.debug("secp521r1-Client-Server-Issuing-CA certificate:\n{}",
				clientSmimeIssuingCa.getCertificate().toString());

		X509Certificate clientCert = testSignClientCertificate(clientServerIssuingCa);
		X509Certificate smimeCert = testSignSmimeCertificate(clientSmimeIssuingCa);
		X509Certificate serverCert = testSignServerCertificate(clientServerIssuingCa);

		testGenerateEmptyCrl(clientServerIssuingCa);
		testGenerateCrl(clientServerIssuingCa, clientCert, smimeCert, serverCert);

		testInitCaFromExisting(clientServerIssuingCa.getCertificate(), clientServerIssuingCa.getKeyPair().getPrivate());
	}

	@Test
	public void testEd25519() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderEd25519()
				.newCa("DE", null, null, null, null, "ed25519-CA").validityPeriod(CertificateAuthority.TEN_YEARS)
				.build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("ed25519-CA certificate:\n{}", ca.getCertificate().toString());

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
		CertificateAuthority ca = CertificateAuthority.builderEd448().newCa("DE", null, null, null, null, "ed448-CA")
				.validityPeriod(CertificateAuthority.TEN_YEARS).build();

		assertNotNull(ca);
		assertNotNull(ca.getKeyPair());
		assertNotNull(ca.getCertificate());
		assertNotNull(ca.initializeKeyPairGenerator());

		logger.debug("ed448-CA certificate:\n{}", ca.getCertificate().toString());

		X509Certificate clientCert = testSignClientCertificate(ca);
		X509Certificate smimeCert = testSignSmimeCertificate(ca);
		X509Certificate serverCert = testSignServerCertificate(ca);

		testGenerateEmptyCrl(ca);
		testGenerateCrl(ca, clientCert, smimeCert, serverCert);

		testInitCaFromExisting(ca.getCertificate(), ca.getKeyPair().getPrivate());
	}

	private X509Certificate testSignClientCertificate(CertificateAuthority ca)
	{
		CertificationRequestBuilder builder = ca.createCertificationRequestBuilder();
		assertNotNull(builder);

		KeyPair keyPair = builder.getKeyPairGenerator().generateKeyPair();
		assertNotNull(keyPair);

		X500Name subject = builder.createName("DE", null, null, null, null, "client");
		assertNotNull(subject);

		JcaPKCS10CertificationRequest request = builder.createCertificationRequest(keyPair, subject, "email@test.com");
		assertNotNull(request);

		X509Certificate certificate = ca.signClientCertificate(request);
		assertNotNull(certificate);

		logger.debug("Client certificate:\n{}", certificate.toString());

		return certificate;
	}

	private X509Certificate testSignSmimeCertificate(CertificateAuthority ca)
	{
		CertificationRequestBuilder builder = ca.createCertificationRequestBuilder();
		assertNotNull(builder);

		KeyPair keyPair = builder.getKeyPairGenerator().generateKeyPair();
		assertNotNull(keyPair);

		X500Name subject = builder.createName("DE", null, null, null, null, "client");
		assertNotNull(subject);

		JcaPKCS10CertificationRequest request = builder.createCertificationRequest(keyPair, subject, "email@test.com");
		assertNotNull(request);

		X509Certificate certificate = ca.signSmimeCertificate(request);
		assertNotNull(certificate);

		logger.debug("S/MIME certificate:\n{}", certificate.toString());

		return certificate;
	}

	private X509Certificate testSignServerCertificate(CertificateAuthority ca)
	{
		CertificationRequestBuilder builder = ca.createCertificationRequestBuilder();
		assertNotNull(builder);

		KeyPair keyPair = builder.getKeyPairGenerator().generateKeyPair();
		assertNotNull(keyPair);

		X500Name subject = builder.createName("DE", null, null, null, null, "server");
		assertNotNull(subject);

		JcaPKCS10CertificationRequest request = builder.createCertificationRequest(keyPair, subject, "email@test.com",
				List.of("server"));
		assertNotNull(request);

		X509Certificate certificate = ca.signServerCertificate(request);
		assertNotNull(certificate);

		logger.debug("Server certificate:\n{}", certificate.toString());

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

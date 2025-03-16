package de.hsheilbronn.mi.utils.crypto.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.Test;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest.CertificationRequestAndPrivateKey;
import de.hsheilbronn.mi.utils.crypto.ca.JcaContentSignerBuilderFactory;
import de.hsheilbronn.mi.utils.crypto.cert.CertificateFormatter.X500PrincipalFormat;
import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class CertificateFormatterTest
{
	private static final CertificateAuthority ca = CertificateAuthority
			.builderSha384EcdsaSecp384r1("DE", null, null, null, null, "JUnit Test CA").build();

	@Test
	void toSubjectName() throws Exception
	{
		X509Certificate cert = ca.getCertificate();
		assertNotNull(cert);

		String subjectCanonical = CertificateFormatter.toSubjectName(cert, X500PrincipalFormat.CANONICAL);
		assertNotNull(subjectCanonical);
		assertEquals("cn=junit test ca,c=de", subjectCanonical);

		String subjectRfc1779 = CertificateFormatter.toSubjectName(cert, X500PrincipalFormat.RFC1779);
		assertNotNull(subjectRfc1779);
		assertEquals("CN=JUnit Test CA, C=DE", subjectRfc1779);

		String subjectRfc2253 = CertificateFormatter.toSubjectName(cert, X500PrincipalFormat.RFC2253);
		assertNotNull(subjectRfc2253);
		assertEquals("CN=JUnit Test CA,C=DE", subjectRfc2253);
	}

	@Test
	void toSubjectNameNull() throws Exception
	{
		X509Certificate cert = ca.getCertificate();
		assertNotNull(cert);

		assertThrows(NullPointerException.class,
				() -> CertificateFormatter.toSubjectName(null, X500PrincipalFormat.CANONICAL));
		assertThrows(NullPointerException.class,
				() -> CertificateFormatter.toSubjectName(null, X500PrincipalFormat.RFC1779));
		assertThrows(NullPointerException.class,
				() -> CertificateFormatter.toSubjectName(null, X500PrincipalFormat.RFC2253));

		assertThrows(NullPointerException.class, () -> CertificateFormatter.toSubjectName(cert, null));
	}

	@Test
	void toOpenSslStyleText() throws Exception
	{
		CertificateAuthority rootCa = CertificateAuthority
				.builder(JcaContentSignerBuilderFactory.sha256WithRsa(), KeyPairGeneratorFactory.rsa1024(),
						CertificateAuthority.createName("DE", null, null, null, null, "JUnit Test Root CA"))
				.build();

		CertificationRequestAndPrivateKey issuingCaReq = CertificationRequest
				.builder(rootCa, "DE", null, null, null, null, "JUnit Test Issuing CA").generateKeyPair().build();
		X509Certificate issuingCaCert = rootCa.signClientServerIssuingCaCertificate(issuingCaReq);
		CertificateAuthority issuingCa = CertificateAuthority.existingCa(issuingCaCert, issuingCaReq.getPrivateKey(),
				List.of(URI.create("https://foo.bar/baz.crl").toURL()));

		CertificationRequestAndPrivateKey serverReq = CertificationRequest
				.builder(issuingCa, "DE", null, null, null, null, "test.server").generateKeyPair()
				.addDnsName("localhost").setEmail("foo@bar.baz").build();
		X509Certificate serverCertificate = issuingCa.signServerCertificate(serverReq);

		assertNotNull(CertificateFormatter.toOpenSslStyleText(rootCa.getCertificate()));
		assertNotNull(CertificateFormatter.toOpenSslStyleText(issuingCaCert));
		assertNotNull(CertificateFormatter.toOpenSslStyleText(serverCertificate));
	}

	@Test
	void toOpenSslStyleTextNull() throws Exception
	{
		assertThrows(NullPointerException.class, () -> CertificateFormatter.toOpenSslStyleText(null));
	}
}

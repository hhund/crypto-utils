package de.hsheilbronn.mi.utils.crypto.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority;
import de.hsheilbronn.mi.utils.crypto.cert.CertificateFormatter.SubjectFormat;

public class CertificateFormatterTest
{
	private static final CertificateAuthority ca = CertificateAuthority
			.builderSha384EcdsaSecp384r1("DE", null, null, null, null, "JUnit Test CA").build();

	@Test
	void getSubjectFromCertificate() throws Exception
	{
		X509Certificate cert = ca.getCertificate();
		assertNotNull(cert);

		String subjectCanonical = CertificateFormatter.getSubjectFromCertificate(cert, SubjectFormat.CANONICAL);
		assertNotNull(subjectCanonical);
		assertEquals("cn=junit test ca,c=de", subjectCanonical);

		String subjectRfc1779 = CertificateFormatter.getSubjectFromCertificate(cert, SubjectFormat.RFC1779);
		assertNotNull(subjectRfc1779);
		assertEquals("CN=JUnit Test CA, C=DE", subjectRfc1779);

		String subjectRfc2253 = CertificateFormatter.getSubjectFromCertificate(cert, SubjectFormat.RFC2253);
		assertNotNull(subjectRfc2253);
		assertEquals("CN=JUnit Test CA,C=DE", subjectRfc2253);
	}

	@Test
	void getSubjectFromCertificateNull() throws Exception
	{
		X509Certificate cert = ca.getCertificate();
		assertNotNull(cert);

		assertThrows(NullPointerException.class,
				() -> CertificateFormatter.getSubjectFromCertificate(null, SubjectFormat.CANONICAL));
		assertThrows(NullPointerException.class,
				() -> CertificateFormatter.getSubjectFromCertificate(null, SubjectFormat.RFC1779));
		assertThrows(NullPointerException.class,
				() -> CertificateFormatter.getSubjectFromCertificate(null, SubjectFormat.RFC2253));

		assertThrows(NullPointerException.class, () -> CertificateFormatter.getSubjectFromCertificate(cert, null));
	}
}

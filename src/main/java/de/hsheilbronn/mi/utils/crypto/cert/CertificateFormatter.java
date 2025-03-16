package de.hsheilbronn.mi.utils.crypto.cert;

import java.security.cert.X509Certificate;
import java.util.Objects;

public class CertificateFormatter
{
	private CertificateFormatter()
	{
	}

	public static enum SubjectFormat
	{
		RFC1779, RFC2253, CANONICAL
	}

	/**
	 * @param certificate
	 *            not <code>null</code>
	 * @param format
	 *            not <code>null</code>
	 * @return
	 */
	public static String getSubjectFromCertificate(X509Certificate certificate, SubjectFormat format)
	{
		Objects.requireNonNull(certificate, "certificate");
		Objects.requireNonNull(format, "format");

		return certificate.getSubjectX500Principal().getName(format.name());
	}
}

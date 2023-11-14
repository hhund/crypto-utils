package de.hsheilbronn.mi.utils.crypto;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

public interface CertificateChecker
{
	String CERTIFICATE_WARNING_LOGGER_NAME = "certificate-warning-logger";

	void checkClientCertificateAndScheduleWarning(KeyStore trustStore, X509Certificate certificate);

	void checkServerCertificateAndScheduleWarning(KeyStore trustStore, X509Certificate certificate);
}

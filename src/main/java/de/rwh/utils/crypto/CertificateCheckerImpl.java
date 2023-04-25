package de.rwh.utils.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateCheckerImpl implements CertificateChecker
{
	private static final Logger logger = LoggerFactory.getLogger(CertificateCheckerImpl.class);
	private static final Logger certificateValidationWarningLogger = LoggerFactory
			.getLogger(CERTIFICATE_WARNING_LOGGER_NAME);

	private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.GERMANY);

	private final ScheduledExecutorService executor;

	/**
	 * @param executor
	 *            not <code>null</code>
	 */
	public CertificateCheckerImpl(ScheduledExecutorService executor)
	{
		Objects.requireNonNull(executor, "executor");

		this.executor = executor;
	}

	@Override
	public void checkClientCertificateAndScheduleWarning(KeyStore trustStore, X509Certificate certificate)
	{
		checkCertificateAndScheduleWarning(trustStore, certificate, true);
	}

	@Override
	public void checkServerCertificateAndScheduleWarning(KeyStore trustStore, X509Certificate certificate)
	{
		checkCertificateAndScheduleWarning(trustStore, certificate, false);
	}

	private void checkCertificateAndScheduleWarning(KeyStore trustStore, X509Certificate certificate,
			boolean clientNotServer)
	{
		try
		{
			TrustManagerFactory trustManagerFactory = TrustManagerFactory
					.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init(trustStore);
			X509TrustManager trustManager = (X509TrustManager) trustManagerFactory.getTrustManagers()[0];

			getCaCertificate(trustStore)
					.forEach(ca -> logger.info("Using CA certificate '{}'. {} to check certificate trust",
							ca.getSubjectDN().toString(), validText(ca)));

			try
			{
				if (clientNotServer)
					trustManager.checkClientTrusted(new X509Certificate[] { certificate }, "RSA");
				else
					trustManager.checkServerTrusted(new X509Certificate[] { certificate }, "RSA");

				logger.info("Certificate '{}' trusted. {}.", getSubjectDn(certificate), validText(certificate));
				scheduleValidationError(certificate);
			}
			catch (Exception e)
			{
				logger.error("Certificate ({}) '{}' not trusted: {}", validText(certificate), getSubjectDn(certificate),
						e.getMessage());
			}

		}
		catch (NoSuchAlgorithmException | KeyStoreException e)
		{
			throw new RuntimeException(e);
		}
	}

	private String getSubjectDn(X509Certificate certificate)
	{
		return certificate.getSubjectX500Principal().getName(X500Principal.RFC1779);
	}

	private List<X509Certificate> getCaCertificate(KeyStore keyStore)
	{
		try
		{
			PKIXParameters params = new PKIXParameters(keyStore);
			return params.getTrustAnchors().stream().map(a -> a.getTrustedCert()).collect(Collectors.toList());
		}
		catch (KeyStoreException | InvalidAlgorithmParameterException e)
		{
			throw new RuntimeException(e);
		}
	}

	private String validText(X509Certificate certificate)
	{
		return "Valid from '" + DATE_FORMAT.format(certificate.getNotBefore()) + "' to '"
				+ DATE_FORMAT.format(certificate.getNotAfter()) + "'";
	}

	private void scheduleValidationError(X509Certificate certificate)
	{
		LocalDateTime notAfter = LocalDateTime.ofInstant(certificate.getNotAfter().toInstant(), ZoneId.systemDefault());
		LocalDateTime notAfterMinus30Days = notAfter.minusDays(30);
		long delay = Math.max(0, Duration.between(LocalDateTime.now(), notAfterMinus30Days).get(ChronoUnit.SECONDS));

		Runnable scheduledWarning = () ->
		{
			long days = Math.max(0, ChronoUnit.DAYS.between(LocalDateTime.now(), notAfter));

			certificateValidationWarningLogger.warn("Certificate '{}'. {}. Will expire in {} day{}!",
					getSubjectDn(certificate), validText(certificate), days, days != 1 ? "s" : "");
		};
		executor.schedule(scheduledWarning, delay, TimeUnit.SECONDS);
	}
}

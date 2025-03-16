package de.hsheilbronn.mi.utils.crypto.cert;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAmount;
import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority;

public final class CertificateValidator
{
	private CertificateValidator()
	{
	}

	private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);

	public static record ExpirationWarning(X509Certificate certificate, ZonedDateTime certificateNotAfter,
			Long daysToExpiry)
	{
	}

	public static Consumer<ExpirationWarning> loggerConsumer(Logger logger)
	{
		return ew ->
		{
			logger.warn("Certificate '{}', valid until {} UTC, will expire in {} day{}!",
					ew.certificate.getSubjectX500Principal().getName(),
					ew.certificateNotAfter.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME), ew.daysToExpiry,
					ew.daysToExpiry != 1 ? "s" : "");
		};
	}

	/**
	 * @param executor
	 *            not <code>null</code>
	 * @param notBeforeWarningLeadTime
	 *            not <code>null</code>
	 * @param certificate
	 *            not <code>null</code>
	 * @param warningConsumer
	 *            not <code>null</code>
	 * @return
	 * @see #loggerConsumer(Logger)
	 */
	public static ScheduledFuture<Void> scheduleExpiryWarning(ScheduledExecutorService executor,
			TemporalAmount notBeforeWarningLeadTime, X509Certificate certificate,
			Consumer<ExpirationWarning> warningConsumer)
	{
		Objects.requireNonNull(executor, "executor");
		Objects.requireNonNull(notBeforeWarningLeadTime, "notBeforeWarningLeadTime");
		Objects.requireNonNull(certificate, "certificate");

		ZonedDateTime notAfter = ZonedDateTime.ofInstant(certificate.getNotAfter().toInstant(), ZoneOffset.UTC);

		Callable<Void> scheduledWarning = () ->
		{
			long days = Math.max(0, ChronoUnit.DAYS.between(ZonedDateTime.now(ZoneOffset.UTC), notAfter));

			warningConsumer.accept(new ExpirationWarning(certificate, notAfter, days));

			return null;
		};

		ZonedDateTime notAfterMinusLeadTime = notAfter.minus(notBeforeWarningLeadTime);
		long delay = Math.max(0, Duration.between(LocalDateTime.now(), notAfterMinusLeadTime).get(ChronoUnit.SECONDS));

		return executor.schedule(scheduledWarning, delay, TimeUnit.SECONDS);
	}

	/**
	 * @param certificate
	 *            not <code>null</code>
	 * @return <code>true</code> if the given <b>certificate</b> not-after field is after {@link ZonedDateTime#now()}
	 */
	public static boolean isCertificateExpired(X509Certificate certificate)
	{
		Objects.requireNonNull(certificate, "certificate");

		return ZonedDateTime.now()
				.isAfter(ZonedDateTime.ofInstant(certificate.getNotAfter().toInstant(), ZoneOffset.UTC));
	}

	public static void vaildateClientCertificate(KeyStore trustStore,
			Collection<? extends X509Certificate> certificateChain) throws CertificateException
	{
		vaildateClientCertificate(trustStore, certificateChain.toArray(X509Certificate[]::new));
	}

	public static void vaildateClientCertificate(KeyStore trustStore, X509Certificate... certificateChain)
			throws CertificateException
	{
		try
		{
			createTrustManager(trustStore).checkClientTrusted(certificateChain, "RSA");
		}
		catch (CertificateException e)
		{
			logger.debug("Client Certificte not valid: {}", e.getMessage());
			throw e;
		}
	}

	public static void vaildateServerCertificate(KeyStore trustStore,
			Collection<? extends X509Certificate> certificateChain) throws CertificateException
	{
		vaildateServerCertificate(trustStore, certificateChain.toArray(X509Certificate[]::new));
	}

	public static void vaildateServerCertificate(KeyStore trustStore, X509Certificate... certificateChain)
			throws CertificateException
	{
		try
		{
			createTrustManager(trustStore).checkServerTrusted(certificateChain, "RSA");
		}
		catch (CertificateException e)
		{
			logger.debug("Server Certificte not valid: {}", e.getMessage());
			throw e;
		}
	}

	private static X509TrustManager createTrustManager(KeyStore trustStore)
	{
		try
		{
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
			tmf.init(trustStore);

			return (X509TrustManager) tmf.getTrustManagers()[0];
		}
		catch (NoSuchAlgorithmException | KeyStoreException e)
		{
			throw new RuntimeException(e);
		}
	}

	public static boolean isClientCertificate(X509Certificate certificate)
	{
		Objects.requireNonNull(certificate, "certificate");

		try
		{
			// digitalSignature && keyEncipherment && client authentication
			return certificate.getKeyUsage() != null && certificate.getKeyUsage()[0] && certificate.getKeyUsage()[2]
					&& certificate.getExtendedKeyUsage()
							.contains(CertificateAuthority.ExtendedKeyUsage.CLIENT_AUTH.toKeyPurposeId().getId());
		}
		catch (CertificateParsingException e)
		{
			throw new RuntimeException(e);
		}
	}

	public static boolean isServerCertificate(X509Certificate certificate)
	{
		Objects.requireNonNull(certificate, "certificate");

		try
		{
			// digitalSignature && keyEncipherment && client authentication
			return certificate.getKeyUsage() != null && certificate.getKeyUsage()[0] && certificate.getKeyUsage()[2]
					&& certificate.getExtendedKeyUsage()
							.contains(CertificateAuthority.ExtendedKeyUsage.SERVER_AUTH.toKeyPurposeId().getId());
		}
		catch (CertificateParsingException e)
		{
			throw new RuntimeException(e);
		}
	}
}

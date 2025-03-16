package de.hsheilbronn.mi.utils.crypto.keystore;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

import de.hsheilbronn.mi.utils.crypto.cert.CertificateFormatter;
import de.hsheilbronn.mi.utils.crypto.cert.CertificateFormatter.X500PrincipalFormat;

public final class KeyStoreFormatter
{
	private KeyStoreFormatter()
	{
	}

	public static record AliasAndResult<T>(String alias, T result)
	{
	}

	public static Map<String, List<String>> toSubjectsFromCertificateChains(KeyStore keyStore,
			X500PrincipalFormat format)
	{
		try
		{
			return Collections.list(keyStore.aliases()).stream().map(toSubjectsFromCertificateChain(keyStore, format))
					.filter(aR -> !aR.result.isEmpty())
					.collect(Collectors.toUnmodifiableMap(AliasAndResult::alias, AliasAndResult::result));
		}
		catch (KeyStoreException e)
		{
			throw new RuntimeException(e);
		}
	}

	private static Function<String, AliasAndResult<List<String>>> toSubjectsFromCertificateChain(KeyStore keyStore,
			X500PrincipalFormat format)
	{
		return alias ->
		{
			try
			{
				Certificate[] certificates = keyStore.getCertificateChain(alias);
				List<String> subjects = certificates == null ? List.of()
						: Arrays.stream(keyStore.getCertificateChain(alias)).filter(c -> c instanceof X509Certificate)
								.map(c -> (X509Certificate) c).map(CertificateFormatter.toSubjectName(format))
								.filter(Objects::nonNull).toList();

				return new AliasAndResult<List<String>>(alias, subjects);
			}
			catch (KeyStoreException e)
			{
				throw new RuntimeException(e);
			}
		};
	}

	public static Map<String, String> toSubjectsFromCertificates(KeyStore keyStore, X500PrincipalFormat format)
	{
		try
		{
			return Collections.list(keyStore.aliases()).stream().map(toSubjectFromCertificate(keyStore, format))
					.filter(aR -> aR.result != null)
					.collect(Collectors.toUnmodifiableMap(AliasAndResult::alias, AliasAndResult::result));
		}
		catch (KeyStoreException e)
		{
			throw new RuntimeException(e);
		}
	}

	private static Function<String, AliasAndResult<String>> toSubjectFromCertificate(KeyStore keyStore,
			X500PrincipalFormat format)
	{
		return alias ->
		{
			try
			{
				Certificate certificate = keyStore.getCertificate(alias);
				String subject = certificate instanceof X509Certificate x
						? CertificateFormatter.toSubjectName(x, format)
						: null;
				return new AliasAndResult<String>(alias, subject);
			}
			catch (KeyStoreException e)
			{
				throw new RuntimeException(e);
			}
		};
	}
}

package de.hsheilbronn.mi.utils.crypto.keystore;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

public final class KeyStoreCreator
{
	private static final String KEY_STORE_TYPE_PKCS12 = "pkcs12";
	private static final String KEY_STORE_TYPE_JKS = "jks";

	private KeyStoreCreator()
	{
	}

	private static KeyStore forPrivateKeyAndCertificateChain(String keyStoreType, PrivateKey key, char[] password,
			Collection<? extends X509Certificate> chain)
	{
		Objects.requireNonNull(chain, "chain");

		return forPrivateKeyAndCertificateChain(keyStoreType, key, password, chain.toArray(X509Certificate[]::new));
	}

	private static KeyStore forPrivateKeyAndCertificateChain(String keyStoreType, PrivateKey key, char[] password,
			X509Certificate... chain)
	{
		Objects.requireNonNull(keyStoreType, "keyStoreType");
		Objects.requireNonNull(key, "key");
		Objects.requireNonNull(password, "password");
		Objects.requireNonNull(chain, "chain");

		if (chain.length == 0)
			throw new IllegalArgumentException("chain empty");

		try
		{
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(null, null);

			String alias = chain[0].getSubjectX500Principal().getName();
			keyStore.setKeyEntry(alias, key, password, chain);

			return keyStore;
		}
		catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	private static KeyStore forTrustedCertificates(String keyStoreType, X509Certificate... certificates)
	{
		Objects.requireNonNull(certificates, "certificates");

		return forTrustedCertificates(keyStoreType, List.of(certificates));
	}

	private static KeyStore forTrustedCertificates(String keyStoreType,
			Collection<? extends X509Certificate> certificates)
	{
		Objects.requireNonNull(keyStoreType, "keyStoreType");
		Objects.requireNonNull(certificates, "certificates");
		if (certificates.isEmpty())
			throw new IllegalArgumentException("certificates empty");

		try
		{
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(null, null);

			for (X509Certificate certificate : certificates)
			{
				String alias = certificate.getSubjectX500Principal().getName();
				keyStore.setCertificateEntry(alias, certificate);
			}

			return keyStore;
		}
		catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	/**
	 * @param key
	 *            not <code>null</code>
	 * @param password
	 *            not <code>null</code>
	 * @param chain
	 *            not <code>null</code>, not empty
	 * @return jks {@link KeyStore} for the given key and chain
	 */
	public static KeyStore jksForPrivateKeyAndCertificateChain(PrivateKey key, char[] password,
			Collection<? extends X509Certificate> chain)
	{
		return forPrivateKeyAndCertificateChain(KEY_STORE_TYPE_JKS, key, password, chain);
	}

	/**
	 * @param key
	 *            not <code>null</code>
	 * @param password
	 *            not <code>null</code>
	 * @param chain
	 *            not <code>null</code>, at least one
	 * @return jks {@link KeyStore} for the given key and chain
	 */
	public static KeyStore jksForPrivateKeyAndCertificateChain(PrivateKey key, char[] password,
			X509Certificate... chain)
	{
		return forPrivateKeyAndCertificateChain(KEY_STORE_TYPE_JKS, key, password, chain);
	}

	/**
	 * @param certificates
	 *            not <code>null</code>, at least one
	 * @return jks {@link KeyStore} for the given certificates
	 */
	public static KeyStore jksForTrustedCertificates(X509Certificate... certificates)
	{

		return forTrustedCertificates(KEY_STORE_TYPE_JKS, certificates);
	}

	/**
	 * @param certificates
	 *            not <code>null</code>, not empty
	 * @return jks {@link KeyStore} for the given certificates
	 */
	public static KeyStore jksForTrustedCertificates(Collection<? extends X509Certificate> certificates)
	{
		return forTrustedCertificates(KEY_STORE_TYPE_JKS, certificates);
	}

	/**
	 * @param key
	 *            not <code>null</code>
	 * @param password
	 *            not <code>null</code>
	 * @param chain
	 *            not <code>null</code>, not empty
	 * @return pkcs12 {@link KeyStore} for the given key and chain
	 */
	public static KeyStore pkcs12ForPrivateKeyAndCertificateChain(PrivateKey key, char[] password,
			Collection<? extends X509Certificate> chain)
	{
		return forPrivateKeyAndCertificateChain(KEY_STORE_TYPE_PKCS12, key, password, chain);
	}

	/**
	 * @param key
	 *            not <code>null</code>
	 * @param password
	 *            not <code>null</code>
	 * @param chain
	 *            not <code>null</code>, at least one
	 * @return pkcs12 {@link KeyStore} for the given key and chain
	 */
	public static KeyStore pkcs12ForPrivateKeyAndCertificateChain(PrivateKey key, char[] password,
			X509Certificate... chain)
	{
		return forPrivateKeyAndCertificateChain(KEY_STORE_TYPE_PKCS12, key, password, chain);
	}

	/**
	 * @param certificates
	 *            not <code>null</code>, at least one
	 * @return pkcs12 {@link KeyStore} for the given certificates
	 */
	public static KeyStore pkcs12ForTrustedCertificates(X509Certificate... certificates)
	{

		return forTrustedCertificates(KEY_STORE_TYPE_PKCS12, certificates);
	}

	/**
	 * @param certificates
	 *            not <code>null</code>, not empty
	 * @return pkcs12 {@link KeyStore} for the given certificates
	 */
	public static KeyStore pkcs12ForTrustedCertificates(Collection<? extends X509Certificate> certificates)
	{
		return forTrustedCertificates(KEY_STORE_TYPE_PKCS12, certificates);
	}
}

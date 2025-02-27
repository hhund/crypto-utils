package de.hsheilbronn.mi.utils.crypto.context;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public final class SSLContextFactory
{
	private SSLContextFactory()
	{
	}

	public static SSLContext createSSLContext(KeyStore trustStore)
			throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException
	{
		return createSSLContext(trustStore, "TLS");
	}

	public static SSLContext createSSLContext(KeyStore trustStore, String protocol)
			throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException
	{
		return createSSLContext(trustStore, null, null, protocol);
	}

	public static SSLContext createSSLContext(KeyStore trustStore, KeyStore keyStore, char[] keyStorePassword)
			throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException
	{
		return createSSLContext(trustStore, keyStore, keyStorePassword, "TLS");
	}

	public static SSLContext createSSLContext(KeyStore trustStore, KeyStore keyStore, char[] keyStorePassword,
			String protocol)
			throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException
	{
		TrustManagerFactory tmf = createTrustManagerFactory(trustStore);
		KeyManagerFactory kmf = createKeyManagerFactory(keyStore, keyStorePassword);

		SSLContext sc = SSLContext.getInstance(protocol);
		sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

		return sc;
	}

	public static TrustManagerFactory createTrustManagerFactory(KeyStore trustStore)
			throws NoSuchAlgorithmException, KeyStoreException
	{
		TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init(trustStore);

		return factory;
	}

	public static KeyManagerFactory createKeyManagerFactory(KeyStore keyStore, char[] keyStorePassword)
			throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException
	{
		KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		factory.init(keyStore, keyStorePassword);

		return factory;
	}
}

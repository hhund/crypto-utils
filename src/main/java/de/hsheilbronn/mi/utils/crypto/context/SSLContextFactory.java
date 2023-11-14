package de.hsheilbronn.mi.utils.crypto.context;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class SSLContextFactory
{
	public SSLContext createSSLContext(KeyStore trustStore)
			throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException
	{
		return createSSLContext(trustStore, null, null);
	}

	public SSLContext createSSLContext(KeyStore trustStore, KeyStore keyStore, char[] keyStorePassword)
			throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException
	{
		TrustManagerFactory tmf = trustStore == null ? null : createTrustManagerFactory();
		if (tmf != null && trustStore != null)
			tmf.init(trustStore);

		KeyManagerFactory kmf = keyStore == null ? null : createKeyManagerFactory();
		if (kmf != null)
			kmf.init(keyStore, keyStorePassword);

		SSLContext sc = SSLContext.getInstance(getProtocol());
		sc.init(kmf != null ? kmf.getKeyManagers() : null, tmf != null ? tmf.getTrustManagers() : null, null);

		return sc;
	}

	/**
	 * Override for non default behavior
	 * 
	 * @return {@link TrustManagerFactory#getInstance(String)} with {@link TrustManagerFactory#getDefaultAlgorithm()}
	 * @throws NoSuchAlgorithmException
	 */
	protected TrustManagerFactory createTrustManagerFactory() throws NoSuchAlgorithmException
	{
		return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
	}

	/**
	 * Override for non default behavior
	 * 
	 * @return {@link KeyManagerFactory#getInstance(String)} with {@link KeyManagerFactory#getDefaultAlgorithm()}
	 * @throws NoSuchAlgorithmException
	 */
	protected KeyManagerFactory createKeyManagerFactory() throws NoSuchAlgorithmException
	{
		return KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
	}

	/**
	 * Override to return other name of the requested protocol from <a href=
	 * "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#sslcontext-algorithms">Java
	 * Security Standard Algorithm Names Specification</a>
	 * 
	 * @return TLS
	 */
	protected String getProtocol()
	{
		return "TLS";
	}
}

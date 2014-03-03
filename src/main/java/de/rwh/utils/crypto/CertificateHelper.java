/**
 * 
 */
package de.rwh.utils.crypto;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * @author hhund
 * 
 */
public final class CertificateHelper
{
	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA512WithRSA";
	private static final String DEFAULT_KEY_ALGORITHM = "RSA";
	private static final int DEFAULT_KEY_SIZE = 4096;

	private CertificateHelper()
	{
	}

	public static void registerBouncyCastleProvider()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	public static KeyPair createRsaKeyPair4096Bit() throws NoSuchAlgorithmException
	{
		return createKeyPair(DEFAULT_KEY_ALGORITHM, DEFAULT_KEY_SIZE);
	}

	public static KeyPair createKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		keyPairGenerator.initialize(keySize);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	public static SubjectKeyIdentifier toSubjectKeyIdentifier(PublicKey publicKey) throws NoSuchAlgorithmException
	{
		return new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
	}

	/**
	 * @param privateKey
	 * @return a SHA512WithRSA content signer for the given private key
	 * @throws OperatorCreationException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @see CertificateHelper#registerBouncyCastleProvider()
	 */
	public static ContentSigner getContentSigner(PrivateKey privateKey) throws OperatorCreationException,
			IllegalStateException
	{
		return getContentSigner(DEFAULT_SIGNATURE_ALGORITHM, privateKey);
	}

	/**
	 * @param signatureAlgorithm
	 * @param privateKey
	 * @return a content signer for the given private key with the given
	 *         signature algorithm
	 * @throws OperatorCreationException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @see CertificateHelper#registerBouncyCastleProvider()
	 */
	public static ContentSigner getContentSigner(String signatureAlgorithm, PrivateKey privateKey)
			throws OperatorCreationException, IllegalStateException
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
			throw new IllegalStateException(String.format("Security provider %s with name %s not found.",
					BouncyCastleProvider.class.getName(), BouncyCastleProvider.PROVIDER_NAME));

		return new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
				privateKey);
	}

	public static KeyStore toCertificateStore(String alias, X509Certificate certificate)
			throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException
	{
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, null);
		keyStore.setCertificateEntry(alias, certificate);
		return keyStore;
	}

	public static KeyStore toJksKeyStore(PrivateKey privateKey, Certificate[] certificate, String certificateAlias,
			String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
	{
		return toKeyStore(privateKey, certificate, certificateAlias, password, "jks");
	}

	public static KeyStore toPkcs12KeyStore(PrivateKey privateKey, Certificate[] certificate, String certificateAlias,
			String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
	{
		return toKeyStore(privateKey, certificate, certificateAlias, password, "pkcs12");
	}

	public static KeyStore toKeyStore(PrivateKey privateKey, Certificate[] certificate, String certificateAlias,
			String password, String keyStoreType) throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException
	{
		KeyStore keyStore = KeyStore.getInstance(keyStoreType);
		keyStore.load(null, null);
		keyStore.setKeyEntry(certificateAlias, privateKey, password.toCharArray(), certificate);
		return keyStore;
	}

	public static KeyStore extractTrust(KeyStore keyStoreIn) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException
	{
		KeyStore keyStore = KeyStore.getInstance("jks");
		keyStore.load(null, null);
		for (X509Certificate caCert : getCaCertificates(keyStoreIn))
			keyStore.setCertificateEntry(UUID.randomUUID().toString(), caCert);

		return keyStore;
	}

	private static List<X509Certificate> getCaCertificates(KeyStore s) throws KeyStoreException
	{
		List<X509Certificate> caCertificates = new ArrayList<>();
		for (Enumeration<String> e = s.aliases(); e.hasMoreElements();)
		{
			String alias = e.nextElement();
			Certificate[] chain = s.getCertificateChain(alias);
			if (chain == null)
				chain = new Certificate[] { s.getCertificate(alias) };

			for (Certificate c : chain)
			{
				if (c instanceof X509Certificate)
				{
					X509Certificate x = (X509Certificate) c;
					if (x.getBasicConstraints() >= 0)
						caCertificates.add(x);
				}
			}
		}
		return caCertificates;
	}
}

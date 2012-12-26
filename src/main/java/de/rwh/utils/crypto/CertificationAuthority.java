/**
 * 
 */
package de.rwh.utils.crypto;

import static de.rwh.utils.crypto.CertificateHelper.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/**
 * @author hhund
 * 
 */
public class CertificationAuthority
{
	public static final long ONE_YEAR_IN_MIILIS = 1000l * 60l * 60l * 24l * 365l;
	public static final long TEN_YEAR_IN_MIILIS = ONE_YEAR_IN_MIILIS * 10l;

	private final X500Name name;

	private X509Certificate caCertificate;
	private KeyPair caKeyPair;

	/**
	 * @param countryCode
	 * @param state
	 * @param locality
	 * @param organization
	 * @param organizationalUnit
	 * @param commonName
	 */
	public CertificationAuthority(String countryCode, String state, String locality, String organization,
			String organizationalUnit, String commonName)
	{
		X500NameBuilder issuerBuilder = new X500NameBuilder(BCStyle.INSTANCE);

		if (countryCode != null && !countryCode.isEmpty())
			issuerBuilder.addRDN(BCStyle.C, countryCode);
		if (state != null && !state.isEmpty())
			issuerBuilder.addRDN(BCStyle.ST, state);
		if (locality != null && !locality.isEmpty())
			issuerBuilder.addRDN(BCStyle.L, locality);
		if (organization != null && !organization.isEmpty())
			issuerBuilder.addRDN(BCStyle.O, organization);
		if (organizationalUnit != null && !organizationalUnit.isEmpty())
			issuerBuilder.addRDN(BCStyle.OU, organizationalUnit);
		if (commonName != null && !commonName.isEmpty())
			issuerBuilder.addRDN(BCStyle.CN, commonName);

		name = issuerBuilder.build();
	}

	/**
	 * Initializes the {@link CertificationAuthority} with a ca certificate
	 * valid from now for 10 Years
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws OperatorCreationException
	 * @throws IOException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @see Security#addProvider(Provider)
	 */
	public void initialize() throws NoSuchAlgorithmException, InvalidKeyException, KeyStoreException,
			CertificateException, OperatorCreationException, IOException, IllegalStateException
	{
		initialize(new Date(), new Date(System.currentTimeMillis() + TEN_YEAR_IN_MIILIS));
	}

	/**
	 * Initializes the {@link CertificationAuthority} with a ca certificate
	 * valid from notBefore to notAfter
	 * 
	 * @param notBefore
	 * @param notAfter
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws OperatorCreationException
	 * @throws IOException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @throw IllegalArgumentException if the given {@link Date}s are not valid
	 * @see Security#addProvider(Provider)
	 */
	public void initialize(Date notBefore, Date notAfter) throws NoSuchAlgorithmException, InvalidKeyException,
			KeyStoreException, CertificateException, OperatorCreationException, IOException, IllegalStateException
	{
		if (notBefore == null || notAfter == null || notAfter.before(notBefore))
			throw new IllegalArgumentException("Dates not valid");

		caKeyPair = createRsaKeyPair();
		caCertificate = createCaCertificate(notBefore, notAfter);
	}

	private X509Certificate createCaCertificate(Date notBefore, Date notAfter) throws NoSuchAlgorithmException,
			KeyStoreException, CertificateException, IOException, InvalidKeyException, OperatorCreationException,
			IllegalStateException
	{
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		PublicKey publicKey = caKeyPair.getPublic();

		JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(name, serial, notBefore,
				notAfter, name, publicKey);

		certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, toSubjectKeyIdentifier(publicKey));
		certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1));
		certificateBuilder
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

		X509CertificateHolder certificateHolder = certificateBuilder.build(getCaContentSigner());

		return toCertificate(certificateHolder);
	}

	private boolean isInitialied()
	{
		return caCertificate != null && caKeyPair != null;
	}

	/**
	 * @return
	 * @throws IllegalStateException
	 *             if the {@link CertificationAuthority} has not bin initialized
	 */
	public X509Certificate getCertificate() throws IllegalStateException
	{
		if (!isInitialied())
			throw new IllegalStateException("not initialized");

		return caCertificate;
	}

	public X509Certificate signWebClientCertificate(JcaPKCS10CertificationRequest request)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, OperatorCreationException,
			CertificateException, InvalidKeyException, IllegalStateException
	{
		if (!isInitialied())
			throw new IllegalStateException("not initialized");

		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);

		return sign(request, keyUsage, extendedKeyUsage);
	}

	public X509Certificate signWebServerCertificate(JcaPKCS10CertificationRequest request)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, OperatorCreationException,
			CertificateException, InvalidKeyException, IllegalStateException
	{
		if (!isInitialied())
			throw new IllegalStateException("not initialized");

		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment
				| KeyUsage.dataEncipherment);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);

		return sign(request, keyUsage, extendedKeyUsage);
	}

	private X509Certificate sign(JcaPKCS10CertificationRequest request, KeyUsage keyUsage,
			ExtendedKeyUsage extendedKeyUsage) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
			CertIOException, OperatorCreationException, CertificateException, InvalidKeyException,
			IllegalStateException
	{
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		Date notBefore = new Date();
		Date notAfter = new Date(notBefore.getTime() + ONE_YEAR_IN_MIILIS);

		PublicKey reqPublicKey = request.getPublicKey();
		X500Principal reqSubject = new X500Principal(request.getSubject().getEncoded());

		JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(caCertificate, serial,
				notBefore, notAfter, reqSubject, reqPublicKey);

		certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		certificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);

		certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, toSubjectKeyIdentifier(reqPublicKey));
		ASN1Encodable subjectAlternativeNames = getSubjectAlternativeNames(request);
		if (subjectAlternativeNames != null)
			certificateBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
		certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, getCaAuthorityKeyIdentifier());
		certificateBuilder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

		X509CertificateHolder certificateHolder = certificateBuilder.build(getCaContentSigner());

		return toCertificate(certificateHolder);
	}

	private ContentSigner getCaContentSigner() throws OperatorCreationException, IllegalStateException
	{
		return getContentSigner(caKeyPair.getPrivate());
	}

	private AuthorityKeyIdentifier getCaAuthorityKeyIdentifier()
	{
		return new AuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded()));
	}

	private static X509Certificate toCertificate(X509CertificateHolder certificateHolder) throws CertificateException
	{
		X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.getCertificate(certificateHolder);

		return certificate;
	}

	private static ASN1Encodable getSubjectAlternativeNames(JcaPKCS10CertificationRequest request)
	{
		Attribute[] attributes = request.getAttributes(Extension.subjectAlternativeName);
		if (attributes.length == 0)
			return null;

		if (attributes.length != 1 || attributes[0].getAttributeValues().length != 1)
			throw new IllegalArgumentException("one subjectAlternativeName field expected");

		return attributes[0].getAttributeValues()[0];
	}
}

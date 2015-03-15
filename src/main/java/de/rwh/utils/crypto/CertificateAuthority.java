/**
 * 
 */
package de.rwh.utils.crypto;

import static de.rwh.utils.crypto.CertificateHelper.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
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
public class CertificateAuthority
{
	public static final long TWO_YEARS_IN_MIILIS = 2000l * 60l * 60l * 24l * 365l;
	public static final long TEN_YEAR_IN_MIILIS = TWO_YEARS_IN_MIILIS * 5l;

	private X500Name name = null;

	private X509Certificate caCertificate;
	private KeyPair caKeyPair;
	private String signatureAlgorithm;

	public static void registerBouncyCastleProvider()
	{
		CertificateHelper.registerBouncyCastleProvider();
	}

	/**
	 * CA with default signature algorithm
	 * {@link CertificateHelper#DEFAULT_SIGNATURE_ALGORITHM}
	 * 
	 * @param caCertificate
	 *            not <code>null</code>
	 * @param caKeyPair
	 *            not <code>null</code>
	 */
	public CertificateAuthority(X509Certificate caCertificate, KeyPair caKeyPair)
	{
		this(caCertificate, caKeyPair, CertificateHelper.DEFAULT_SIGNATURE_ALGORITHM);
	}

	/**
	 * @param caCertificate
	 *            not <code>null</code>
	 * @param caKeyPair
	 *            not <code>null</code>
	 * @param signatureAlgorithm
	 *            not <code>null</code>
	 */
	public CertificateAuthority(X509Certificate caCertificate, KeyPair caKeyPair, String signatureAlgorithm)
	{
		this.caCertificate = caCertificate;
		this.caKeyPair = caKeyPair;
		this.signatureAlgorithm = signatureAlgorithm;
	}

	/**
	 * @param countryCode
	 * @param state
	 * @param locality
	 * @param organization
	 * @param organizationalUnit
	 * @param commonName
	 */
	public CertificateAuthority(String countryCode, String state, String locality, String organization,
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
	 * Initializes the {@link CertificateAuthority} with a ca certificate valid
	 * from now for 10 Years, with default values for encryption algorithm, key
	 * size and signature algorithm. See {@link CertificateHelper} constants.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws OperatorCreationException
	 * @throws CertIOException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @throws IllegalStateException
	 *             if this {@link CertificateAuthority} is already initialized
	 * @see CertificateAuthority#registerBouncyCastleProvider()
	 * @see CertificateAuthority#isInitialized()
	 */
	public void initialize() throws NoSuchAlgorithmException, InvalidKeyException, KeyStoreException,
			CertificateException, OperatorCreationException, CertIOException, IllegalStateException
	{
		initialize(new Date(), new Date(System.currentTimeMillis() + TEN_YEAR_IN_MIILIS), DEFAULT_KEY_SIZE,
				DEFAULT_SIGNATURE_ALGORITHM);
	}

	/**
	 * Initializes the {@link CertificateAuthority} with a ca certificate valid
	 * from notBefore to notAfter, with default values for encryption algorithm,
	 * key size and signature algorithm. See {@link CertificateHelper}
	 * constants.
	 * 
	 * @param notBefore
	 * @param notAfter
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws OperatorCreationException
	 * @throws CertIOException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @throws IllegalStateException
	 *             if this {@link CertificateAuthority} is already initialized
	 * @throws IllegalArgumentException
	 *             if the given {@link Date}s are not valid
	 * @see CertificateAuthority#registerBouncyCastleProvider()
	 * @see CertificateAuthority#isInitialized()
	 */
	public void initialize(Date notBefore, Date notAfter) throws NoSuchAlgorithmException, InvalidKeyException,
			KeyStoreException, CertificateException, OperatorCreationException, CertIOException, IllegalStateException
	{
		if (notBefore == null || notAfter == null || notAfter.before(notBefore))
			throw new IllegalArgumentException("Dates not valid");

		if (isInitialized())
			throw new IllegalStateException("already initialized");

		initialize(notBefore, notAfter, DEFAULT_KEY_SIZE, DEFAULT_SIGNATURE_ALGORITHM);
	}

	/**
	 * Initializes the {@link CertificateAuthority} with a ca certificate valid
	 * from notBefore to notAfter, with default value for encryption algorithm.
	 * See {@link CertificateHelper} constants.
	 * 
	 * @param notBefore
	 *            not <code>null</code>
	 * @param notAfter
	 *            not <code>null</code>
	 * @param keySize
	 *            <code>> 0</code>
	 * @param signatureAlgorithm
	 *            not <code>null</code>
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws OperatorCreationException
	 * @throws CertIOException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @throws IllegalStateException
	 *             if this {@link CertificateAuthority} is already initialized
	 * @throws IllegalArgumentException
	 *             if the given {@link Date}s are not valid
	 * @see CertificateAuthority#registerBouncyCastleProvider()
	 * @see CertificateAuthority#isInitialized()
	 * @see CertificateHelper#createRsaKeyPair4096Bit()
	 */
	public void initialize(Date notBefore, Date notAfter, int keySize, String signatureAlgorithm)
			throws NoSuchAlgorithmException, InvalidKeyException, KeyStoreException, CertificateException,
			CertIOException, OperatorCreationException, IllegalStateException
	{
		if (notBefore == null || notAfter == null || notAfter.before(notBefore))
			throw new IllegalArgumentException("Dates not valid");

		if (keySize <= 0)
			throw new IllegalArgumentException("Key size not valid");

		if (isInitialized())
			throw new IllegalStateException("already initialized");

		this.signatureAlgorithm = signatureAlgorithm;

		caKeyPair = createKeyPair(DEFAULT_KEY_ALGORITHM, keySize);
		caCertificate = createCaCertificate(notBefore, notAfter);
	}

	private X509Certificate createCaCertificate(Date notBefore, Date notAfter) throws NoSuchAlgorithmException,
			KeyStoreException, CertificateException, CertIOException, InvalidKeyException, OperatorCreationException,
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

	private boolean isInitialized()
	{
		return caCertificate != null && caKeyPair != null;
	}

	/**
	 * @return the ca certificate
	 * @throws IllegalStateException
	 *             if the {@link CertificateAuthority} has not bin initialized
	 */
	public X509Certificate getCertificate() throws IllegalStateException
	{
		if (!isInitialized())
			throw new IllegalStateException("not initialized");

		return caCertificate;
	}

	/**
	 * @return the ca key pair
	 * @throws IllegalStateException
	 *             if the {@link CertificateAuthority} has not bin initialized
	 */
	public KeyPair getCaKeyPair()
	{
		if (!isInitialized())
			throw new IllegalStateException("not initialized");

		return caKeyPair;
	}

	/**
	 * @return <code>null</code> if this {@link CertificateAuthority} is created
	 *         via
	 *         {@link CertificateAuthority#CertificateAuthority(X509Certificate, KeyPair)}
	 */
	public X500Name getName()
	{
		return name;
	}

	/**
	 * Signs the given request, client certificate is valid for two years
	 * 
	 * @param request
	 *            not <code>null</code>
	 * @return signed client certificate
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @see CertificateAuthority#isInitialized()
	 */
	public X509Certificate signWebClientCertificate(JcaPKCS10CertificationRequest request)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, OperatorCreationException,
			CertificateException, InvalidKeyException, IllegalStateException
	{
		return signWebClientCertificate(request, TWO_YEARS_IN_MIILIS);
	}

	/**
	 * Signs the given request, client certificate is valid for the given amount
	 * of time in milliseconds
	 * 
	 * @param request
	 *            not <code>null</code>
	 * @param validityPeriodInMilliseconds
	 *            > 0
	 * @return signed client certificate
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @see CertificateAuthority#isInitialized()
	 */
	public X509Certificate signWebClientCertificate(JcaPKCS10CertificationRequest request,
			long validityPeriodInMilliseconds) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException,
			OperatorCreationException, CertificateException, InvalidKeyException, IllegalStateException
	{
		if (!isInitialized())
			throw new IllegalStateException("not initialized");

		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);

		return sign(request, keyUsage, extendedKeyUsage, validityPeriodInMilliseconds);
	}

	/**
	 * Signs the given request, server certificate is valid for two years
	 * 
	 * @param request
	 *            not <code>null</code>
	 * @return signed server certificate
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @see CertificateAuthority#isInitialized()
	 */
	public X509Certificate signWebServerCertificate(JcaPKCS10CertificationRequest request)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, OperatorCreationException,
			CertificateException, InvalidKeyException, IllegalStateException
	{
		return signWebServerCertificate(request, TWO_YEARS_IN_MIILIS);
	}

	/**
	 * Signs the given request, server certificate is valid for the given amount
	 * of time in milliseconds
	 * 
	 * @param request
	 *            not <code>null</code>
	 * @param validityPeriodInMilliseconds
	 *            > 0
	 * @return signed server certificate
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @see CertificateAuthority#isInitialized()
	 */
	public X509Certificate signWebServerCertificate(JcaPKCS10CertificationRequest request,
			long validityPeriodInMilliseconds) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException,
			OperatorCreationException, CertificateException, InvalidKeyException, IllegalStateException
	{
		if (!isInitialized())
			throw new IllegalStateException("not initialized");

		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
				| KeyUsage.dataEncipherment);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);

		return sign(request, keyUsage, extendedKeyUsage, validityPeriodInMilliseconds);
	}

	private X509Certificate sign(JcaPKCS10CertificationRequest request, KeyUsage keyUsage,
			ExtendedKeyUsage extendedKeyUsage, long validityPeriodInMilliseconds) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException, CertIOException, OperatorCreationException,
			CertificateException, InvalidKeyException, IllegalStateException
	{
		Objects.requireNonNull(request, "request");
		if (validityPeriodInMilliseconds <= 0)
			throw new IllegalArgumentException("validityPeriodInMilliseconds must be > 0");

		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		Date notBefore = new Date();
		Date notAfter = new Date(notBefore.getTime() + validityPeriodInMilliseconds);

		PublicKey reqPublicKey = request.getPublicKey();
		X500Principal reqSubject = new X500Principal(CertificationRequestBuilder.createSubject(
				getDnElement(request.getSubject(), BCStyle.C), getDnElement(request.getSubject(), BCStyle.ST),
				getDnElement(request.getSubject(), BCStyle.L), getDnElement(request.getSubject(), BCStyle.O),
				getDnElement(request.getSubject(), BCStyle.OU), getDnElement(request.getSubject(), BCStyle.CN))
				.getEncoded());

		JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(caCertificate, serial,
				notBefore, notAfter, reqSubject, reqPublicKey);

		certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		certificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);

		certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, toSubjectKeyIdentifier(reqPublicKey));
		GeneralNames subjectAlternativeNames = getSubjectAlternativeNames(request);
		if (subjectAlternativeNames != null)
			certificateBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
		certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, getCaAuthorityKeyIdentifier());
		certificateBuilder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

		X509CertificateHolder certificateHolder = certificateBuilder.build(getCaContentSigner());

		return toCertificate(certificateHolder);
	}

	private ContentSigner getCaContentSigner() throws OperatorCreationException, IllegalStateException
	{
		return getContentSigner(signatureAlgorithm, caKeyPair.getPrivate());
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

	/**
	 * @param request
	 *            not <code>null</code>
	 * @return might be <code>null</code>
	 */
	public static GeneralNames getSubjectAlternativeNames(JcaPKCS10CertificationRequest request) throws IOException
	{
		List<GeneralName> generalNames = new ArrayList<GeneralName>();

		// -- from e-mail in subject DN
		String email = getDnElement(request.getSubject(), BCStyle.E);
		if (email != null && !email.isEmpty())
			generalNames.add(new GeneralName(GeneralName.rfc822Name, email));

		// -- from CSR extensions
		Attribute[] extensionRequestAttributes = request
				.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);

		for (Attribute a : extensionRequestAttributes)
		{
			for (ASN1Encodable v1 : a.getAttributeValues())
			{
				if (v1 instanceof DERSequence)
				{
					DERSequence s1 = (DERSequence) v1;
					for (int i1 = 0; i1 < s1.size(); i1++)
					{
						ASN1Encodable v2 = s1.getObjectAt(i1);
						if (v2 instanceof DERSequence)
						{
							DERSequence s2 = (DERSequence) v2;
							if (s2.size() >= 2)
							{
								ASN1Encodable objectAt0 = s2.getObjectAt(0);
								ASN1Encodable objectAt1 = s2.getObjectAt(1);

								if (objectAt0 instanceof ASN1ObjectIdentifier && objectAt1 instanceof DEROctetString)
								{
									ASN1ObjectIdentifier at0 = (ASN1ObjectIdentifier) objectAt0;
									if (Extension.subjectAlternativeName.equals(at0))
									{
										DEROctetString at1 = (DEROctetString) objectAt1;
										ASN1Primitive asn1at1 = toDERObject(at1);
										if (asn1at1 instanceof DLSequence)
										{
											DLSequence asn1at1DLSequence = (DLSequence) asn1at1;
											for (int i3 = 0; i3 < asn1at1DLSequence.size(); i3++)
											{
												ASN1Encodable v3 = asn1at1DLSequence.getObjectAt(i3);
												if (v3 instanceof DERTaggedObject)
												{
													GeneralName name = new GeneralName(
															((DERTaggedObject) v3).getTagNo(), v3);
													generalNames.add(name);
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// -- from subjectAlternativeName extension - not standard conform
		Attribute[] subjectAlternativeNameAttributes = request.getAttributes(Extension.subjectAlternativeName);
		for (Attribute a : subjectAlternativeNameAttributes)
		{
			for (ASN1Encodable v : a.getAttributeValues())
			{
				if (v instanceof DERSequence)
				{
					DERSequence s = (DERSequence) v;
					for (int i = 0; i < s.size(); i++)
					{
						ASN1Encodable encodable = s.getObjectAt(i);
						if (encodable instanceof DERTaggedObject)
						{
							GeneralName name = new GeneralName(((DERTaggedObject) encodable).getTagNo(), encodable);
							generalNames.add(name);
						}
					}
				}
			}
		}

		if (generalNames.isEmpty())
			return null;
		else
			return new GeneralNames(generalNames.toArray(new GeneralName[generalNames.size()]));
	}

	private static ASN1Primitive toDERObject(DEROctetString o) throws IOException
	{
		byte[] data = o.getOctets();
		ByteArrayInputStream inStream = new ByteArrayInputStream(data);
		try (ASN1InputStream asnInputStream = new ASN1InputStream(inStream))
		{
			return asnInputStream.readObject();
		}
	}

	/**
	 * For DN specific OIDs see {@link BCStyle} constants
	 * 
	 * @param subject
	 *            not <code>null</code>
	 * @param oid
	 *            not <code>null</code>
	 * @return <code>null</code> if <code>subject</code> does not contain an
	 *         element for the given <code>oid</code>
	 * @see BCStyle
	 */
	public static String getDnElement(X500Name subject, ASN1ObjectIdentifier oid)
	{
		RDN[] rdNs = subject.getRDNs(oid);
		if (rdNs.length > 0)
			return IETFUtils.valueToString(rdNs[0].getFirst().getValue());
		else
			return null;
	}
}

package de.hsheilbronn.mi.utils.crypto.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.LocalDateTime;
import java.time.Period;
import java.time.ZoneId;
import java.time.temporal.TemporalAmount;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class CertificateAuthority
{
	public static JcaContentSignerBuilder contentSignerBuilder(String signatureAlgorith)
	{
		return new JcaContentSignerBuilder(signatureAlgorith);
	}

	public static JcaContentSignerBuilder contentSignerBuilderSha256WithRsa()
	{
		return new JcaContentSignerBuilder("SHA256WithRSA");
	}

	public static JcaContentSignerBuilder contentSignerBuilderSha512WithRsa()
	{
		return new JcaContentSignerBuilder("SHA512WithRSA");
	}

	public static JcaContentSignerBuilder contentSignerBuilderSha256withEcdsa()
	{
		return new JcaContentSignerBuilder("SHA256withECDSA");
	}

	public static JcaContentSignerBuilder contentSignerBuilderSha384withEcdsa()
	{
		return new JcaContentSignerBuilder("SHA384withECDSA");
	}

	public static JcaContentSignerBuilder contentSignerBuilderSha512withEcdsa()
	{
		return new JcaContentSignerBuilder("SHA512withECDSA");
	}

	public static JcaContentSignerBuilder contentSignerBuilderEd25519()
	{
		return new JcaContentSignerBuilder("Ed25519");
	}

	public static JcaContentSignerBuilder contentSignerBuilderEd448()
	{
		return new JcaContentSignerBuilder("Ed448");
	}

	/**
	 * Keys: RSA 3072 Bit, Signature Algorithm: SHA512WithRSA
	 * 
	 * @return ca builder
	 */
	public static Builder builderSha256Rsa3072()
	{
		JcaContentSignerBuilder contentSignerBuilder = contentSignerBuilderSha256WithRsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.rsa3072();

		return new Builder(contentSignerBuilder, keyPairGenertorFactory);
	}

	/**
	 * Keys: RSA 4096 Bit, Signature Algorithm: SHA256WithRSA
	 * 
	 * @return ca builder
	 */
	public static Builder builderSha512Rsa4096()
	{
		JcaContentSignerBuilder contentSignerBuilder = contentSignerBuilderSha512WithRsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.rsa4096();

		return new Builder(contentSignerBuilder, keyPairGenertorFactory);
	}

	/**
	 * Keys: secp384r1, Signature algorithm: SHA384withECDSA
	 * 
	 * @return ca builder
	 */
	public static Builder builderSha384EcdsaSecp384r1()
	{
		JcaContentSignerBuilder contentSignerBuilder = contentSignerBuilderSha384withEcdsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.secp384r1();

		return new Builder(contentSignerBuilder, keyPairGenertorFactory);
	}

	/**
	 * Keys: secp521r1, Signature algorithm: SHA512withECDSA Note: secp521r1 not widely supported by webbrowsers
	 * 
	 * @return ca builder
	 */
	public static Builder builderSha512EcdsaSecp521r1()
	{
		JcaContentSignerBuilder contentSignerBuilder = contentSignerBuilderSha512withEcdsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.secp521r1();

		return new Builder(contentSignerBuilder, keyPairGenertorFactory);
	}

	/**
	 * Keys: ed25519, Signature algorithm: Ed25519 Note: ed25519 not supported by webbrowsers
	 * 
	 * @return ca builder
	 */
	public static Builder builderEd25519()
	{
		JcaContentSignerBuilder contentSignerBuilder = contentSignerBuilderEd25519();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.ed25519();

		return new Builder(contentSignerBuilder, keyPairGenertorFactory);
	}

	/**
	 * Keys: ed448, Signature algorithm: Ed448
	 * 
	 * @return ca builder
	 */
	public static Builder builderEd448()
	{
		JcaContentSignerBuilder contentSignerBuilder = contentSignerBuilderEd448();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.ed448();

		return new Builder(contentSignerBuilder, keyPairGenertorFactory);
	}

	public static CertificateAuthority existingCa(X509Certificate caCertificate, PrivateKey caPrivateKey)
	{
		JcaContentSignerBuilder contentSignerBuilder = contentSignerBuilder(caCertificate.getSigAlgName());

		KeyPairGeneratorFactory keyPairGeneratorFactory;
		if (caPrivateKey instanceof RSAPrivateKey rsa)
			keyPairGeneratorFactory = KeyPairGeneratorFactory.rsa(rsa.getModulus().bitLength());
		else if (caPrivateKey instanceof ECPrivateKey ec)
			keyPairGeneratorFactory = new KeyPairGeneratorFactory(ec.getAlgorithm(), ec.getParams());
		else if (caPrivateKey instanceof EdECPrivateKey ed)
			keyPairGeneratorFactory = new KeyPairGeneratorFactory(ed.getAlgorithm(), ed.getParams());
		else
			throw new IllegalArgumentException("Key algorithm '" + caPrivateKey.getAlgorithm() + "' not supported");

		return new Builder(contentSignerBuilder, keyPairGeneratorFactory).existingCa(caCertificate, caPrivateKey);
	}

	public static class Builder
	{
		private final JcaContentSignerBuilder contentSignerBuilder;
		private final KeyPairGeneratorFactory keyPairGeneratorFactory;

		private Builder(JcaContentSignerBuilder contentSignerBuilder, KeyPairGeneratorFactory keyPairGeneratorFactory)
		{
			this.contentSignerBuilder = contentSignerBuilder;
			this.keyPairGeneratorFactory = keyPairGeneratorFactory;
		}

		/**
		 * @param caCertificate
		 *            not <code>null</code>
		 * @param caPrivateKey
		 *            not <code>null</code>
		 * @return
		 */
		public CertificateAuthority existingCa(X509Certificate caCertificate, PrivateKey caPrivateKey)
		{
			KeyPair caKeyPair = new KeyPair(caCertificate.getPublicKey(), caPrivateKey);

			return new CertificateAuthority(contentSignerBuilder, keyPairGeneratorFactory, caCertificate, caKeyPair);
		}

		public CaBuilder newCa(String countryCode, String state, String locality, String organization,
				String organizationalUnit, String commonName)
		{
			X500Name name = new CertificationRequestBuilder(contentSignerBuilder, keyPairGeneratorFactory)
					.createName(countryCode, state, locality, organization, organizationalUnit, commonName);

			return new CaBuilder(this, name);
		}

		public CaBuilder newCa(X500Name name)
		{
			return new CaBuilder(this, name);
		}

		public static class CaBuilder
		{
			private final Builder builder;
			private final X500Name caName;

			private TemporalAmount caValidityPeriod = TEN_YEARS;

			private CaBuilder(Builder builder, X500Name caName)
			{
				this.builder = builder;
				this.caName = caName;
			}

			/**
			 * Default {@link CertificateAuthority#TEN_YEARS}
			 * 
			 * @param validityPeriod
			 *            not <code>null</code>
			 * @return this CaBuilder
			 */
			public CaBuilder validityPeriod(TemporalAmount validityPeriod)
			{
				this.caValidityPeriod = Objects.requireNonNull(validityPeriod, "caValidityPeriod");

				return this;
			}

			/**
			 * @return CA valid for 10 years
			 * @see CertificateAuthority#TEN_YEARS
			 */
			public CertificateAuthority build()
			{
				KeyPair caKeyPair = builder.keyPairGeneratorFactory.initialize().generateKeyPair();
				X509Certificate caCertificate = createCaCertificate(caKeyPair);

				return new CertificateAuthority(builder.contentSignerBuilder, builder.keyPairGeneratorFactory,
						caCertificate, caKeyPair);
			}

			private X509Certificate createCaCertificate(KeyPair keyPair)
			{
				PublicKey publicKey = keyPair.getPublic();
				PrivateKey privateKey = keyPair.getPrivate();

				LocalDateTime notBefore = LocalDateTime.now();
				LocalDateTime notAfter = notBefore.plus(caValidityPeriod);

				X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(caName, createSerial(),
						toDate(notBefore), toDate(notAfter), caName,
						SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(publicKey.getEncoded())));

				try
				{
					certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
							new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey));
					certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
					certificateBuilder.addExtension(Extension.keyUsage, true,
							new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

					ContentSigner contentSigner = builder.contentSignerBuilder.build(privateKey);
					X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
					X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);

					return certificate;
				}
				catch (CertIOException | NoSuchAlgorithmException | OperatorCreationException | CertificateException e)
				{
					throw new RuntimeException(e);
				}
			}
		}
	}

	private static Date toDate(LocalDateTime dateTime)
	{
		return Date.from(dateTime.atZone(ZoneId.systemDefault()).toInstant());
	}

	private static BigInteger createSerial()
	{
		return new BigInteger(UUID.randomUUID().toString().replaceAll("-", ""), 16);
	}

	public static enum RevocationReason
	{
		UNSPECIFIED(0), //
		KEY_COMPROMISE(1), CA_COMPROMISE(2), AFFILIATION_CHANGED(3), //
		SUPERSEDED(4), CESSATION_OF_OPERATION(5), CERTIFICATE_HOLD(6), //
		REMOVE_FROM_CRL(8), PRIVILEGE_WITHDRAWN(9), AA_COMPROMISE(10);

		private final int value;

		private RevocationReason(int value)
		{
			this.value = value;
		}

		public CRLReason toCRLReason()
		{
			return CRLReason.lookup(value);
		}
	}

	public record RevocationEntry(X509Certificate certificate, LocalDateTime revocationDate, RevocationReason reason)
	{
	}

	public static final TemporalAmount ONE_YEAR = Period.ofYears(1);
	public static final TemporalAmount FIVE_YEARS = Period.ofYears(5);
	public static final TemporalAmount TEN_YEARS = Period.ofYears(10);
	public static final TemporalAmount SEVEN_DAYS = Period.ofDays(7);

	private final JcaContentSignerBuilder contentSignerBuilder;
	private final KeyPairGeneratorFactory keyPairGeneratorFactory;
	private final X509Certificate certificate;
	private final KeyPair keyPair;

	private CertificateAuthority(JcaContentSignerBuilder contentSignerBuilder,
			KeyPairGeneratorFactory keyPairGeneratorFactory, X509Certificate caCertificate, KeyPair caKeyPair)
	{
		this.contentSignerBuilder = contentSignerBuilder;
		this.keyPairGeneratorFactory = keyPairGeneratorFactory;
		this.certificate = caCertificate;
		this.keyPair = caKeyPair;
	}

	public JcaContentSignerBuilder getContentSignerBuilder()
	{
		return contentSignerBuilder;
	}

	public KeyPairGeneratorFactory getKeyPairGeneratorFactory()
	{
		return keyPairGeneratorFactory;
	}

	public KeyPairGenerator initializeKeyPairGenerator()
	{
		return keyPairGeneratorFactory.initialize();
	}

	/**
	 * @return the CAs certificate
	 * @throws IllegalStateException
	 *             if the {@link CertificateAuthority} has not bin initialized
	 */
	public X509Certificate getCertificate() throws IllegalStateException
	{
		return certificate;
	}

	/**
	 * @return the CAs key pair
	 * @throws IllegalStateException
	 *             if the {@link CertificateAuthority} has not bin initialized
	 */
	public KeyPair getKeyPair()
	{
		return keyPair;
	}

	public CertificationRequestBuilder createCertificationRequestBuilder()
	{
		return new CertificationRequestBuilder(contentSignerBuilder, keyPairGeneratorFactory);
	}

	public static CertificationRequestBuilder createCertificationRequestBuilder(
			JcaContentSignerBuilder contentSignerBuilder, KeyPairGeneratorFactory keyPairGeneratorFactory)
	{
		return new CertificationRequestBuilder(contentSignerBuilder, keyPairGeneratorFactory);
	}

	public X509Certificate signClientServerIssuingCaCertificate(JcaPKCS10CertificationRequest request)
	{
		return signClientServerIssuingCaCertificate(request, FIVE_YEARS);
	}

	public X509Certificate signClientServerIssuingCaCertificate(JcaPKCS10CertificationRequest request,
			TemporalAmount validityPeriod)
	{
		return signClientServerIssuingCaCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	public X509Certificate signClientServerIssuingCaCertificate(JcaPKCS10CertificationRequest request,
			TemporalAmount validityPeriod, Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
				new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth });

		return sign(request, keyUsage, extendedKeyUsage, new BasicConstraints(0), validityPeriod,
				requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	public X509Certificate signClientSmimeIssuingCaCertificate(JcaPKCS10CertificationRequest request)
	{
		return signClientSmimeIssuingCaCertificate(request, FIVE_YEARS);
	}

	public X509Certificate signClientSmimeIssuingCaCertificate(JcaPKCS10CertificationRequest request,
			TemporalAmount validityPeriod)
	{
		return signClientSmimeIssuingCaCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	public X509Certificate signClientSmimeIssuingCaCertificate(JcaPKCS10CertificationRequest request,
			TemporalAmount validityPeriod, Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
				new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection });

		return sign(request, keyUsage, extendedKeyUsage, new BasicConstraints(0), validityPeriod,
				requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	public X509Certificate signClientCertificate(JcaPKCS10CertificationRequest request)
	{
		return signClientCertificate(request, ONE_YEAR);
	}

	public X509Certificate signClientCertificate(JcaPKCS10CertificationRequest request, TemporalAmount validityPeriod)
	{
		return signClientCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	public X509Certificate signClientCertificate(JcaPKCS10CertificationRequest request, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		KeyUsage keyUsage = new KeyUsage(
				KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);

		return sign(request, keyUsage, extendedKeyUsage, new BasicConstraints(false), validityPeriod,
				requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	public X509Certificate signServerCertificate(JcaPKCS10CertificationRequest request)
	{
		return signServerCertificate(request, ONE_YEAR);
	}

	public X509Certificate signServerCertificate(JcaPKCS10CertificationRequest request, TemporalAmount validityPeriod)
	{
		return signServerCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	public X509Certificate signServerCertificate(JcaPKCS10CertificationRequest request, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
				| KeyUsage.dataEncipherment);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);

		return sign(request, keyUsage, extendedKeyUsage, new BasicConstraints(false), validityPeriod,
				requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	private X509Certificate sign(JcaPKCS10CertificationRequest request, KeyUsage keyUsage,
			ExtendedKeyUsage extendedKeyUsage, BasicConstraints basicConstraints, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		Objects.requireNonNull(request, "request");
		Objects.requireNonNull(request.getSubject(), "request.subject");
		Objects.requireNonNull(keyUsage, "keyUsage");
		Objects.requireNonNull(extendedKeyUsage, "extendedKeyUsage");
		Objects.requireNonNull(basicConstraints, "basicConstraints");
		Objects.requireNonNull(validityPeriod, "validityPeriod");
		Objects.requireNonNull(requestSubjectNameModifier, "requestSubjectNameModifier");
		Objects.requireNonNull(requestSubjectAlternativeNamesModifier, "requestSubjectAlternativeNamesModifier");

		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plus(validityPeriod);

		X500Name subject = requestSubjectNameModifier.apply(request.getSubject());
		Objects.requireNonNull(request.getSubject(), "subject after modification");

		try
		{
			Objects.requireNonNull(request.getPublicKey(), "request.publicKey");
			PublicKey reqPublicKey = request.getPublicKey();
			List<GeneralName> subjectAlternativeNames = requestSubjectAlternativeNamesModifier
					.apply(getSubjectAlternativeNames(request));

			JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(certificate,
					createSerial(), toDate(notBefore), toDate(notAfter), subject, reqPublicKey);

			certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
					createSubjectKeyIdentifier(reqPublicKey));
			certificateBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
			certificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);
			if (subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty())
			{
				GeneralNames names = new GeneralNames(subjectAlternativeNames.toArray(GeneralName[]::new));
				certificateBuilder.addExtension(Extension.subjectAlternativeName, false, names);
			}

			certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyIdentifier());
			certificateBuilder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

			ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());
			X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
			X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);

			return certificate;
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | OperatorCreationException | CertificateException
				| IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	private SubjectKeyIdentifier createSubjectKeyIdentifier(PublicKey publicKey) throws NoSuchAlgorithmException
	{
		return new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
	}

	private AuthorityKeyIdentifier createAuthorityKeyIdentifier() throws NoSuchAlgorithmException
	{
		return new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(keyPair.getPublic());
	}

	/**
	 * @param request
	 *            not <code>null</code>
	 * @return unmodifiable {@link List}, never <code>null</code>
	 * @throws IOException
	 */
	public static List<GeneralName> getSubjectAlternativeNames(JcaPKCS10CertificationRequest request) throws IOException
	{
		Objects.requireNonNull(request, "request");

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
												else if (v3 instanceof DLTaggedObject)
												{
													GeneralName name = new GeneralName(((DLTaggedObject) v3).getTagNo(),
															v3);
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

		return Collections.unmodifiableList(generalNames);
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
	 * @return <code>null</code> if <code>subject</code> does not contain an element for the given <code>oid</code>
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

	public X509CRL createEmptyRevocationList()
	{
		return createEmptyRevocationList(SEVEN_DAYS);
	}

	public X509CRL createEmptyRevocationList(TemporalAmount nextUpdateIn)
	{
		return createRevocationList(List.of(), nextUpdateIn);
	}

	public X509CRL createRevocationList(List<RevocationEntry> entries)
	{
		return createRevocationList(entries, SEVEN_DAYS);
	}

	public X509CRL createRevocationList(List<RevocationEntry> entries, TemporalAmount nextUpdateIn)
	{
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime nextUpdate = now.plus(nextUpdateIn);

		X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(certificate.getSubjectX500Principal(), toDate(now));
		crlBuilder.setNextUpdate(toDate(nextUpdate));

		try
		{
			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(certificate));

			ExtensionsGenerator generator = new ExtensionsGenerator();
			if (entries != null)
				entries.forEach(e -> crlBuilder.addCRLEntry(e.certificate().getSerialNumber(),
						toDate(e.revocationDate()), generate(generator, e)));

			JcaX509CRLConverter converter = new JcaX509CRLConverter();
			return converter.getCRL(crlBuilder.build(contentSignerBuilder.build(keyPair.getPrivate())));
		}
		catch (CertificateEncodingException | NoSuchAlgorithmException | CertIOException | CRLException
				| OperatorCreationException e)
		{
			throw new RuntimeException(e);
		}
	}

	private Extensions generate(ExtensionsGenerator generator, RevocationEntry entry)
	{
		try
		{
			generator.addExtension(Extension.reasonCode, false, entry.reason().toCRLReason());
			return generator.generate();
		}
		catch (IOException e)
		{
			throw new RuntimeException(e);
		}
		finally
		{
			generator.reset();
		}
	}
}

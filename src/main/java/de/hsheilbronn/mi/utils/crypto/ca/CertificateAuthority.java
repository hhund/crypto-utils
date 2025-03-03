package de.hsheilbronn.mi.utils.crypto.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
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
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
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
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
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
	public static enum KeyUsage
	{
		//@formatter:off
		DIGITAL_SIGNATURE(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature),
		NON_REPUDIATION(org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation),
		KEY_ENCIPHERMENT(org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment),
		DATA_ENCIPHERMENT(org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment),
		KEY_AGREEMENT(org.bouncycastle.asn1.x509.KeyUsage.keyAgreement),
		KEY_CERT_SIGN(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign),
		CRL_SIGN(org.bouncycastle.asn1.x509.KeyUsage.cRLSign),
		ENCIPHER_ONLY(org.bouncycastle.asn1.x509.KeyUsage.encipherOnly),
		DECIPHER_ONLY(org.bouncycastle.asn1.x509.KeyUsage.decipherOnly);
		//@formatter:on

		private final int value;

		private KeyUsage(int value)
		{
			this.value = value;
		}

		public static final EnumSet<KeyUsage> DIGITAL_SIGNATURE_AND_KEY_ENCIPHERMENT = EnumSet.of(DIGITAL_SIGNATURE,
				KEY_ENCIPHERMENT);
		public static final EnumSet<KeyUsage> KEY_CERT_SIGN_AND_CRL_SIGN = EnumSet.of(KeyUsage.KEY_CERT_SIGN,
				KeyUsage.CRL_SIGN);

		public int getValue()
		{
			return value;
		}
	}

	public static enum ExtendedKeyUsage
	{
		//@formatter:off
		SERVER_AUTH(KeyPurposeId.id_kp_serverAuth),
		CLIENT_AUTH(KeyPurposeId.id_kp_clientAuth),
		CODE_SIGNING(KeyPurposeId.id_kp_codeSigning),
		EMAIL_PROTECTION(KeyPurposeId.id_kp_emailProtection),
		IPSEC_END_SYSTEM(KeyPurposeId.id_kp_ipsecEndSystem),
		IPSEC_TUNNEL(KeyPurposeId.id_kp_ipsecTunnel),
		IPSEC_USER(KeyPurposeId.id_kp_ipsecUser),
		TIME_STAMPING(KeyPurposeId.id_kp_timeStamping),
		OCSP_SIGNING(KeyPurposeId.id_kp_OCSPSigning),
		DVCS(KeyPurposeId.id_kp_dvcs),
		SBGP_CERT_AA_SERVER_AUTH(KeyPurposeId.id_kp_sbgpCertAAServerAuth),
		SCVP_RESPONDER(KeyPurposeId.id_kp_scvp_responder),
		EAP_OVER_PPP(KeyPurposeId.id_kp_eapOverPPP),
		EAP_OVER_LAN(KeyPurposeId.id_kp_eapOverLAN),
		SCVP_SERVER(KeyPurposeId.id_kp_scvpServer),
		SCVP_CLIENT(KeyPurposeId.id_kp_scvpClient),
		IPSEC_IKE(KeyPurposeId.id_kp_ipsecIKE),
		CAPWAP_AC(KeyPurposeId.id_kp_capwapAC),
		CAPWAP_WTP(KeyPurposeId.id_kp_capwapWTP),
		CMC_CA(KeyPurposeId.id_kp_cmcCA),
		CMC_RA(KeyPurposeId.id_kp_cmcRA),
		CM_KGA(KeyPurposeId.id_kp_cmKGA),
		SMARTCARD_LOGON(KeyPurposeId.id_kp_smartcardlogon),
		MAC_ADDRESS(KeyPurposeId.id_kp_macAddress),
		MS_SGC(KeyPurposeId.id_kp_msSGC),
		NS_SGC(KeyPurposeId.id_kp_nsSGC);
		//@formatter:on

		private final KeyPurposeId value;

		private ExtendedKeyUsage(KeyPurposeId value)
		{
			this.value = value;
		}

		public KeyPurposeId toKeyPurposeId()
		{
			return value;
		}
	}

	public static enum RevocationReason
	{
		//@formatter:off
		UNSPECIFIED(CRLReason.unspecified),
		KEY_COMPROMISE(CRLReason.keyCompromise),
		CA_COMPROMISE(CRLReason.cACompromise),
		AFFILIATION_CHANGED(CRLReason.affiliationChanged),
		SUPERSEDED(CRLReason.superseded),
		CESSATION_OF_OPERATION(CRLReason.cessationOfOperation),
		CERTIFICATE_HOLD(CRLReason.certificateHold),
		REMOVE_FROM_CRL(CRLReason.removeFromCRL),
		PRIVILEGE_WITHDRAWN(CRLReason.privilegeWithdrawn),
		AA_COMPROMISE(CRLReason.aACompromise);
		//@formatter:on

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

	/**
	 * Keys: RSA 3072 Bit, Signature Algorithm: SHA512WithRSA
	 * 
	 * @param countryCode
	 *            may be <code>null</code>
	 * @param state
	 *            may be <code>null</code>
	 * @param locality
	 *            may be <code>null</code>
	 * @param organization
	 *            may be <code>null</code>
	 * @param organizationalUnit
	 *            may be <code>null</code>
	 * @param commonName
	 *            not <code>null</code>, not {@link String#isBlank()}
	 * @return new {@link CertificateAuthorityBuilder}
	 */
	public static CertificateAuthorityBuilder builderSha256Rsa3072(String countryCode, String state, String locality,
			String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.sha256WithRsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.rsa3072();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Keys: RSA 4096 Bit, Signature Algorithm: SHA256WithRSA
	 * 
	 * @param countryCode
	 *            may be <code>null</code>
	 * @param state
	 *            may be <code>null</code>
	 * @param locality
	 *            may be <code>null</code>
	 * @param organization
	 *            may be <code>null</code>
	 * @param organizationalUnit
	 *            may be <code>null</code>
	 * @param commonName
	 *            not <code>null</code>, not {@link String#isBlank()}
	 * @return new {@link CertificateAuthorityBuilder}
	 */
	public static CertificateAuthorityBuilder builderSha512Rsa4096(String countryCode, String state, String locality,
			String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.sha512WithRsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.rsa4096();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Keys: secp384r1, Signature algorithm: SHA384withECDSA
	 * 
	 * @param countryCode
	 *            may be <code>null</code>
	 * @param state
	 *            may be <code>null</code>
	 * @param locality
	 *            may be <code>null</code>
	 * @param organization
	 *            may be <code>null</code>
	 * @param organizationalUnit
	 *            may be <code>null</code>
	 * @param commonName
	 *            not <code>null</code>, not {@link String#isBlank()}
	 * @return new {@link CertificateAuthorityBuilder}
	 */
	public static CertificateAuthorityBuilder builderSha384EcdsaSecp384r1(String countryCode, String state,
			String locality, String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.sha384withEcdsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.secp384r1();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Keys: secp521r1, Signature algorithm: SHA512withECDSA Note: secp521r1 not widely supported by webbrowsers
	 * 
	 * @param countryCode
	 *            may be <code>null</code>
	 * @param state
	 *            may be <code>null</code>
	 * @param locality
	 *            may be <code>null</code>
	 * @param organization
	 *            may be <code>null</code>
	 * @param organizationalUnit
	 *            may be <code>null</code>
	 * @param commonName
	 *            not <code>null</code>, not {@link String#isBlank()}
	 * @return new {@link CertificateAuthorityBuilder}
	 */
	public static CertificateAuthorityBuilder builderSha512EcdsaSecp521r1(String countryCode, String state,
			String locality, String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.sha512withEcdsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.secp521r1();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Keys: ed25519, Signature algorithm: Ed25519 Note: ed25519 not supported by webbrowsers
	 * 
	 * @param countryCode
	 *            may be <code>null</code>
	 * @param state
	 *            may be <code>null</code>
	 * @param locality
	 *            may be <code>null</code>
	 * @param organization
	 *            may be <code>null</code>
	 * @param organizationalUnit
	 *            may be <code>null</code>
	 * @param commonName
	 *            not <code>null</code>, not {@link String#isBlank()}
	 * @return new {@link CertificateAuthorityBuilder}
	 */
	public static CertificateAuthorityBuilder builderEd25519(String countryCode, String state, String locality,
			String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.ed25519();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.ed25519();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Keys: ed448, Signature algorithm: Ed448
	 * 
	 * @param countryCode
	 *            may be <code>null</code>
	 * @param state
	 *            may be <code>null</code>
	 * @param locality
	 *            may be <code>null</code>
	 * @param organization
	 *            may be <code>null</code>
	 * @param organizationalUnit
	 *            may be <code>null</code>
	 * @param commonName
	 *            not <code>null</code>, not {@link String#isBlank()}
	 * @return new {@link CertificateAuthorityBuilder}
	 */
	public static CertificateAuthorityBuilder builderEd448(String countryCode, String state, String locality,
			String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.ed448();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.ed448();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * @param countryCode
	 *            may be <code>null</code>
	 * @param state
	 *            may be <code>null</code>
	 * @param locality
	 *            may be <code>null</code>
	 * @param organization
	 *            may be <code>null</code>
	 * @param organizationalUnit
	 *            may be <code>null</code>
	 * @param commonName
	 *            not <code>null</code>, not {@link String#isBlank()}
	 * @return X500 Name with non <code>null</code>, non blank elements
	 */
	public static X500Name createName(String countryCode, String state, String locality, String organization,
			String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");
		if (commonName.isBlank())
			throw new IllegalArgumentException("commonName blank");

		X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);

		if (countryCode != null && !countryCode.isBlank())
			subjectBuilder.addRDN(BCStyle.C, countryCode);
		if (state != null && !state.isBlank())
			subjectBuilder.addRDN(BCStyle.ST, state);
		if (locality != null && !locality.isBlank())
			subjectBuilder.addRDN(BCStyle.L, locality);
		if (organization != null && !organization.isBlank())
			subjectBuilder.addRDN(BCStyle.O, organization);
		if (organizationalUnit != null && !organizationalUnit.isBlank())
			subjectBuilder.addRDN(BCStyle.OU, organizationalUnit);

		subjectBuilder.addRDN(BCStyle.CN, commonName);

		return subjectBuilder.build();
	}

	/**
	 * @param contentSignerBuilder
	 *            not <code>null</code>
	 * @param keyPairGenertorFactory
	 *            not <code>null</code>
	 * @param name
	 *            not <code>null</code>
	 * @return new {@link CertificateAuthorityBuilder}
	 * @see JcaContentSignerBuilderFactory
	 */
	public static CertificateAuthorityBuilder builder(JcaContentSignerBuilder contentSignerBuilder,
			KeyPairGeneratorFactory keyPairGenertorFactory, X500Name name)
	{
		return new CertificateAuthorityBuilder(contentSignerBuilder, keyPairGenertorFactory, name);
	}

	/**
	 * @param certificate
	 *            not <code>null</code>
	 * @param privateKey
	 *            not <code>null</code>
	 * @param crlDistributionPoints
	 *            may be <code>null</code>
	 * @return {@link CertificateAuthority} for the given <b>certificate</b>, <b>privateKey</b> and
	 *         <b>crlDistributionPoints</b>, {@link JcaContentSignerBuilder} and {@link KeyPairGeneratorFactory} derived
	 *         from the given <b>certificate</b>
	 */
	public static CertificateAuthority existingCa(X509Certificate certificate, PrivateKey privateKey,
			List<URL> crlDistributionPoints)
	{
		Objects.requireNonNull(certificate, "certificate");
		Objects.requireNonNull(privateKey, "privateKey");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory
				.algorithm(certificate.getSigAlgName());

		KeyPairGeneratorFactory keyPairGeneratorFactory;
		if (privateKey instanceof RSAPrivateKey rsa)
			keyPairGeneratorFactory = KeyPairGeneratorFactory.rsa(rsa.getModulus().bitLength());
		else if (privateKey instanceof ECPrivateKey ec)
			keyPairGeneratorFactory = new KeyPairGeneratorFactory(ec.getAlgorithm(), ec.getParams());
		else if (privateKey instanceof EdECPrivateKey ed)
			keyPairGeneratorFactory = new KeyPairGeneratorFactory(ed.getAlgorithm(), ed.getParams());
		else
			throw new IllegalArgumentException("Key algorithm '" + privateKey.getAlgorithm() + "' not supported");

		KeyPair keyPair = new KeyPair(certificate.getPublicKey(), privateKey);

		return new CertificateAuthority(contentSignerBuilder, keyPairGeneratorFactory, certificate, keyPair,
				crlDistributionPoints);
	}

	public static final class CertificateAuthorityBuilder
	{
		private final JcaContentSignerBuilder contentSignerBuilder;
		private final KeyPairGeneratorFactory keyPairGeneratorFactory;
		private final X500Name name;

		private final List<URL> crlDistributionPoints = new ArrayList<>();
		private TemporalAmount caValidityPeriod = TEN_YEARS;

		private final EnumSet<KeyUsage> keyUsages = KeyUsage.KEY_CERT_SIGN_AND_CRL_SIGN;

		private final EnumSet<ExtendedKeyUsage> extendedKeyUsages = EnumSet.of(ExtendedKeyUsage.CLIENT_AUTH,
				ExtendedKeyUsage.EMAIL_PROTECTION, ExtendedKeyUsage.SERVER_AUTH, ExtendedKeyUsage.TIME_STAMPING,
				ExtendedKeyUsage.OCSP_SIGNING);

		private CertificateAuthorityBuilder(JcaContentSignerBuilder contentSignerBuilder,
				KeyPairGeneratorFactory keyPairGeneratorFactory, X500Name name)
		{
			Objects.requireNonNull(contentSignerBuilder, "contentSignerBuilder");
			Objects.requireNonNull(keyPairGeneratorFactory, "keyPairGeneratorFactory");
			Objects.requireNonNull(name, "name");

			this.contentSignerBuilder = contentSignerBuilder;
			this.keyPairGeneratorFactory = keyPairGeneratorFactory;
			this.name = name;
		}

		/**
		 * Default {@link CertificateAuthority#TEN_YEARS}
		 * 
		 * @param caValidityPeriod
		 *            does nothing if <code>null</code>
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder setValidityPeriod(TemporalAmount caValidityPeriod)
		{
			if (caValidityPeriod != null)
				this.caValidityPeriod = caValidityPeriod;

			return this;
		}

		/**
		 * @param url
		 *            not <code>null</code>
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder addCrlDistributionPoint(URL url)
		{
			Objects.requireNonNull(url, "url");

			crlDistributionPoints.add(url);

			return this;
		}

		/**
		 * Clears crlDistributionPoints property and sets all from the given collection.
		 * 
		 * @param urls
		 *            ignores <code>null</code> values
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder setCrlDistributionPoints(URL... urls)
		{
			setCrlDistributionPoints(List.of(urls));

			return this;
		}

		/**
		 * Clears crlDistributionPoints property and sets all from the given collection.
		 * 
		 * @param urls
		 *            not <code>null</code>, ignores <code>null</code> values
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder setCrlDistributionPoints(Collection<? extends URL> urls)
		{
			Objects.requireNonNull(urls, "urls");

			crlDistributionPoints.clear();
			crlDistributionPoints.addAll(urls.stream().filter(Objects::nonNull).toList());

			return this;
		}

		/**
		 * @param keyUsage
		 *            not <code>null</code>
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder addKeyUsage(KeyUsage keyUsage)
		{
			Objects.requireNonNull(keyUsage, "keyUsage");

			this.keyUsages.add(keyUsage);

			return this;
		}

		/**
		 * Clears keyUsage property and sets all from the given collection.
		 * 
		 * @param keyUsages
		 *            ignores <code>null</code> values
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder setKeyUsages(KeyUsage... keyUsages)
		{
			setKeyUsages(List.of(keyUsages));

			return this;
		}

		/**
		 * Clears keyUsage property and sets all from the given collection.
		 * 
		 * @param keyUsages
		 *            not <code>null</code>, ignores <code>null</code> value
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder setKeyUsages(Collection<KeyUsage> keyUsages)
		{
			Objects.requireNonNull(keyUsages, "keyUsages");

			this.keyUsages.clear();
			this.keyUsages.addAll(keyUsages.stream().filter(Objects::nonNull).toList());

			return this;
		}

		/**
		 * @param extendedKeyUsage
		 *            not <code>null</code>
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder addExtendedKeyUsage(ExtendedKeyUsage extendedKeyUsage)
		{
			Objects.requireNonNull(extendedKeyUsage, "extendedKeyUsage");

			this.extendedKeyUsages.add(extendedKeyUsage);

			return this;
		}

		/**
		 * Clears extendedKeyUsage property and sets all from the given collection.
		 * 
		 * @param extendedKeyUsages
		 *            ignores <code>null</code> value
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder setExtendedKeyUsages(ExtendedKeyUsage... extendedKeyUsages)
		{
			setExtendedKeyUsages(List.of(extendedKeyUsages));

			return this;
		}

		/**
		 * Clears extendedKeyUsage property and sets all from the given collection.
		 * 
		 * @param extendedKeyUsages
		 *            not <code>null</code>, ignores <code>null</code> value
		 * @return this {@link CertificateAuthorityBuilder}
		 */
		public CertificateAuthorityBuilder setExtendedKeyUsages(Collection<ExtendedKeyUsage> extendedKeyUsages)
		{
			Objects.requireNonNull(extendedKeyUsages, "extendedKeyUsages");

			this.extendedKeyUsages.clear();
			this.extendedKeyUsages.addAll(extendedKeyUsages.stream().filter(Objects::nonNull).toList());

			return this;
		}

		public CertificateAuthority build()
		{
			KeyPair caKeyPair = keyPairGeneratorFactory.initialize().generateKeyPair();
			X509Certificate caCertificate = createCaCertificate(caKeyPair);

			return new CertificateAuthority(contentSignerBuilder, keyPairGeneratorFactory, caCertificate, caKeyPair,
					crlDistributionPoints);
		}

		private X509Certificate createCaCertificate(KeyPair keyPair)
		{
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();

			LocalDateTime notBefore = LocalDateTime.now();
			LocalDateTime notAfter = notBefore.plus(caValidityPeriod);

			X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(name, createSerial(),
					toDate(notBefore), toDate(notAfter), name,
					SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(publicKey.getEncoded())));

			try
			{
				certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
						new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey));
				certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

				certificateBuilder.addExtension(Extension.keyUsage, true, new org.bouncycastle.asn1.x509.KeyUsage(
						keyUsages.stream().mapToInt(KeyUsage::getValue).reduce((a, b) -> a | b).getAsInt()));

				certificateBuilder.addExtension(Extension.extendedKeyUsage, false,
						new org.bouncycastle.asn1.x509.ExtendedKeyUsage(extendedKeyUsages.stream()
								.map(ExtendedKeyUsage::toKeyPurposeId).toArray(KeyPurposeId[]::new)));

				ContentSigner contentSigner = contentSignerBuilder.build(privateKey);
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

	private static Date toDate(LocalDateTime dateTime)
	{
		return Date.from(dateTime.atZone(ZoneId.systemDefault()).toInstant());
	}

	private static BigInteger createSerial()
	{
		return new BigInteger(UUID.randomUUID().toString().replaceAll("-", ""), 16);
	}

	private final JcaContentSignerBuilder contentSignerBuilder;
	private final KeyPairGeneratorFactory keyPairGeneratorFactory;

	private final X509Certificate caCertificate;
	private final KeyPair keyPair;
	private final List<URL> crlDistributionPoints = new ArrayList<>();

	private CertificateAuthority(JcaContentSignerBuilder contentSignerBuilder,
			KeyPairGeneratorFactory keyPairGeneratorFactory, X509Certificate caCertificate, KeyPair caKeyPair,
			List<URL> crlDistributionPoints)
	{
		this.contentSignerBuilder = contentSignerBuilder;
		this.keyPairGeneratorFactory = keyPairGeneratorFactory;

		this.caCertificate = caCertificate;
		this.keyPair = caKeyPair;

		if (crlDistributionPoints != null)
			this.crlDistributionPoints.addAll(crlDistributionPoints);
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

	public X509Certificate getCertificate()
	{
		return caCertificate;
	}

	public KeyPair getKeyPair()
	{
		return keyPair;
	}

	public List<URL> getCrlDistributionPoints()
	{
		return Collections.unmodifiableList(crlDistributionPoints);
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @return CA certificate for issuing client and server certificates, valid for {@link #FIVE_YEARS}
	 * @see #signServerIssuingCaCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signServerIssuingCaCertificate(CertificationRequest request)
	{
		return signServerIssuingCaCertificate(request, FIVE_YEARS, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @return CA certificate for issuing client and server certificates
	 * @see #signServerIssuingCaCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signServerIssuingCaCertificate(CertificationRequest request, TemporalAmount validityPeriod)
	{
		return signServerIssuingCaCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @param requestSubjectNameModifier
	 *            not <code>null</code>
	 * @param requestSubjectAlternativeNamesModifier
	 *            not <code>null</code>
	 * @return CA certificate for issuing client and server certificates
	 * @see KeyUsage#KEY_CERT_SIGN
	 * @see KeyUsage#CRL_SIGN
	 * @see ExtendedKeyUsage#SERVER_AUTH
	 * @see #signCertificate(CertificationRequest, Set, Set, BasicConstraints, TemporalAmount, Function, Function)
	 */
	public X509Certificate signServerIssuingCaCertificate(CertificationRequest request, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		return signCertificate(request, KeyUsage.KEY_CERT_SIGN_AND_CRL_SIGN,
				EnumSet.of(ExtendedKeyUsage.CLIENT_AUTH, ExtendedKeyUsage.SERVER_AUTH), new BasicConstraints(0),
				validityPeriod, requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @return CA certificate for issuing client and server certificates, valid for {@link #FIVE_YEARS}
	 * @see #signClientServerIssuingCaCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientServerIssuingCaCertificate(CertificationRequest request)
	{
		return signClientServerIssuingCaCertificate(request, FIVE_YEARS, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @return CA certificate for issuing client and server certificates
	 * @see #signClientServerIssuingCaCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientServerIssuingCaCertificate(CertificationRequest request,
			TemporalAmount validityPeriod)
	{
		return signClientServerIssuingCaCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @param requestSubjectNameModifier
	 *            not <code>null</code>
	 * @param requestSubjectAlternativeNamesModifier
	 *            not <code>null</code>
	 * @return CA certificate for issuing client and server certificates
	 * @see KeyUsage#KEY_CERT_SIGN
	 * @see KeyUsage#CRL_SIGN
	 * @see ExtendedKeyUsage#CLIENT_AUTH
	 * @see ExtendedKeyUsage#SERVER_AUTH
	 * @see #signCertificate(CertificationRequest, Set, Set, BasicConstraints, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientServerIssuingCaCertificate(CertificationRequest request,
			TemporalAmount validityPeriod, Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		return signCertificate(request, KeyUsage.KEY_CERT_SIGN_AND_CRL_SIGN,
				EnumSet.of(ExtendedKeyUsage.CLIENT_AUTH, ExtendedKeyUsage.SERVER_AUTH), new BasicConstraints(0),
				validityPeriod, requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @return CA certificate for issuing client and S/MIME certificates, valid for {@link #FIVE_YEARS}
	 * @see #signClientSmimeIssuingCaCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientSmimeIssuingCaCertificate(CertificationRequest request)
	{
		return signClientSmimeIssuingCaCertificate(request, FIVE_YEARS, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @return CA certificate for issuing client and S/MIME certificates
	 * @see #signClientSmimeIssuingCaCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientSmimeIssuingCaCertificate(CertificationRequest request,
			TemporalAmount validityPeriod)
	{
		return signClientSmimeIssuingCaCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @param requestSubjectNameModifier
	 *            not <code>null</code>
	 * @param requestSubjectAlternativeNamesModifier
	 *            not <code>null</code>
	 * @return CA certificate for issuing client and S/MIME certificates
	 * @see KeyUsage#KEY_CERT_SIGN
	 * @see KeyUsage#CRL_SIGN
	 * @see ExtendedKeyUsage#CLIENT_AUTH
	 * @see ExtendedKeyUsage#EMAIL_PROTECTION
	 * @see #signCertificate(CertificationRequest, Set, Set, BasicConstraints, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientSmimeIssuingCaCertificate(CertificationRequest request,
			TemporalAmount validityPeriod, Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		return signCertificate(request, KeyUsage.KEY_CERT_SIGN_AND_CRL_SIGN,
				EnumSet.of(ExtendedKeyUsage.CLIENT_AUTH, ExtendedKeyUsage.EMAIL_PROTECTION), new BasicConstraints(0),
				validityPeriod, requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @return signed client certificate valid for {@link #ONE_YEAR}
	 * @see #signClientCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientCertificate(CertificationRequest request)
	{
		return signClientCertificate(request, ONE_YEAR, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @return signed client certificate
	 * @see #signClientCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientCertificate(CertificationRequest request, TemporalAmount validityPeriod)
	{
		return signClientCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @param requestSubjectNameModifier
	 *            not <code>null</code>
	 * @param requestSubjectAlternativeNamesModifier
	 *            not <code>null</code>
	 * @return signed client certificate
	 * @see KeyUsage#DIGITAL_SIGNATURE
	 * @see KeyUsage#KEY_ENCIPHERMENT
	 * @see ExtendedKeyUsage#CLIENT_AUTH
	 * @see #signCertificate(CertificationRequest, Set, Set, BasicConstraints, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientCertificate(CertificationRequest request, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		return signCertificate(request, KeyUsage.DIGITAL_SIGNATURE_AND_KEY_ENCIPHERMENT,
				EnumSet.of(ExtendedKeyUsage.CLIENT_AUTH), new BasicConstraints(false), validityPeriod,
				requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @return signed client and S/MIME certificate valid for {@link #ONE_YEAR}
	 * @see #signClientSmimeCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientSmimeCertificate(CertificationRequest request)
	{
		return signClientSmimeCertificate(request, ONE_YEAR, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @return signed client and S/MIME certificate
	 * @see #signClientSmimeCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientSmimeCertificate(CertificationRequest request, TemporalAmount validityPeriod)
	{
		return signClientSmimeCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @param requestSubjectNameModifier
	 *            not <code>null</code>
	 * @param requestSubjectAlternativeNamesModifier
	 *            not <code>null</code>
	 * @return signed client and S/MIME certificate
	 * @see KeyUsage#DIGITAL_SIGNATURE
	 * @see KeyUsage#KEY_ENCIPHERMENT
	 * @see ExtendedKeyUsage#CLIENT_AUTH
	 * @see ExtendedKeyUsage#EMAIL_PROTECTION
	 * @see #signCertificate(CertificationRequest, Set, Set, BasicConstraints, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientSmimeCertificate(CertificationRequest request, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		return signCertificate(request, KeyUsage.DIGITAL_SIGNATURE_AND_KEY_ENCIPHERMENT,
				EnumSet.of(ExtendedKeyUsage.CLIENT_AUTH, ExtendedKeyUsage.EMAIL_PROTECTION),
				new BasicConstraints(false), validityPeriod, requestSubjectNameModifier,
				requestSubjectAlternativeNamesModifier);
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @return signed S/MIME certificate valid for {@link #ONE_YEAR}
	 * @see #signSmimeCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signSmimeCertificate(CertificationRequest request)
	{
		return signSmimeCertificate(request, ONE_YEAR, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @return signed S/MIME certificate
	 * @see #signSmimeCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signSmimeCertificate(CertificationRequest request, TemporalAmount validityPeriod)
	{
		return signSmimeCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @param requestSubjectNameModifier
	 *            not <code>null</code>
	 * @param requestSubjectAlternativeNamesModifier
	 *            not <code>null</code>
	 * @return signed S/MIME certificate
	 * @see KeyUsage#DIGITAL_SIGNATURE
	 * @see KeyUsage#KEY_ENCIPHERMENT
	 * @see ExtendedKeyUsage#EMAIL_PROTECTION
	 * @see #signCertificate(CertificationRequest, Set, Set, BasicConstraints, TemporalAmount, Function, Function)
	 */
	public X509Certificate signSmimeCertificate(CertificationRequest request, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		return signCertificate(request, KeyUsage.DIGITAL_SIGNATURE_AND_KEY_ENCIPHERMENT,
				EnumSet.of(ExtendedKeyUsage.EMAIL_PROTECTION), new BasicConstraints(false), validityPeriod,
				requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @return signed server certificate valid for {@link #ONE_YEAR}
	 * @see #signServerCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signServerCertificate(CertificationRequest request)
	{
		return signServerCertificate(request, ONE_YEAR, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @return signed server certificate
	 * @see #signServerCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signServerCertificate(CertificationRequest request, TemporalAmount validityPeriod)
	{
		return signServerCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @param requestSubjectNameModifier
	 *            not <code>null</code>
	 * @param requestSubjectAlternativeNamesModifier
	 *            not <code>null</code>
	 * @return signed server certificate
	 * @see KeyUsage#DIGITAL_SIGNATURE
	 * @see KeyUsage#KEY_ENCIPHERMENT
	 * @see ExtendedKeyUsage#SERVER_AUTH
	 * @see #signCertificate(CertificationRequest, Set, Set, BasicConstraints, TemporalAmount, Function, Function)
	 */
	public X509Certificate signServerCertificate(CertificationRequest request, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		return signCertificate(request, KeyUsage.DIGITAL_SIGNATURE_AND_KEY_ENCIPHERMENT,
				EnumSet.of(ExtendedKeyUsage.SERVER_AUTH), new BasicConstraints(false), validityPeriod,
				requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @return signed client and server certificate valid for {@link #ONE_YEAR}
	 * @see #signClientServerCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientServerCertificate(CertificationRequest request)
	{
		return signClientServerCertificate(request, ONE_YEAR, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @return signed client and server certificate
	 * @see #signClientServerCertificate(CertificationRequest, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientServerCertificate(CertificationRequest request, TemporalAmount validityPeriod)
	{
		return signClientServerCertificate(request, validityPeriod, Function.identity(), Function.identity());
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @param requestSubjectNameModifier
	 *            not <code>null</code>
	 * @param requestSubjectAlternativeNamesModifier
	 *            not <code>null</code>
	 * @return signed client and server certificate
	 * @see KeyUsage#DIGITAL_SIGNATURE
	 * @see KeyUsage#KEY_ENCIPHERMENT
	 * @see ExtendedKeyUsage#CLIENT_AUTH
	 * @see ExtendedKeyUsage#SERVER_AUTH
	 * @see #signCertificate(CertificationRequest, Set, Set, BasicConstraints, TemporalAmount, Function, Function)
	 */
	public X509Certificate signClientServerCertificate(CertificationRequest request, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
	{
		return signCertificate(request, KeyUsage.DIGITAL_SIGNATURE_AND_KEY_ENCIPHERMENT,
				EnumSet.of(ExtendedKeyUsage.CLIENT_AUTH, ExtendedKeyUsage.SERVER_AUTH), new BasicConstraints(false),
				validityPeriod, requestSubjectNameModifier, requestSubjectAlternativeNamesModifier);
	}

	/**
	 * @param request
	 *            not <code>null</code>, request.subject not <code>null</code>, request.publicKey not <code>null</code>
	 * @param keyUsage
	 *            not <code>null</code>
	 * @param extendedKeyUsage
	 *            not <code>null</code>
	 * @param basicConstraints
	 *            not <code>null</code>
	 * @param validityPeriod
	 *            not <code>null</code>
	 * @param requestSubjectNameModifier
	 *            not <code>null</code>
	 * @param requestSubjectAlternativeNamesModifier
	 *            not <code>null</code>
	 * @return signed {@link X509Certificate}
	 * @throws RuntimeException
	 *             if signing fails with {@link InvalidKeyException}, {@link NoSuchAlgorithmException},
	 *             {@link OperatorCreationException}, {@link CertificateException} or {@link IOException}
	 */
	public X509Certificate signCertificate(CertificationRequest request, Set<KeyUsage> keyUsage,
			Set<ExtendedKeyUsage> extendedKeyUsage, BasicConstraints basicConstraints, TemporalAmount validityPeriod,
			Function<X500Name, X500Name> requestSubjectNameModifier,
			Function<List<GeneralName>, List<GeneralName>> requestSubjectAlternativeNamesModifier)
			throws RuntimeException
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

		List<GeneralName> subjectAlternativeNames = requestSubjectAlternativeNamesModifier
				.apply(getSubjectAlternativeNames(request.getRequest()));
		Objects.requireNonNull(subjectAlternativeNames, "subjectAlternativeNames after modification");

		try
		{
			Objects.requireNonNull(request.getPublicKey(), "request.publicKey");
			PublicKey reqPublicKey = request.getPublicKey();

			JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(caCertificate,
					createSerial(), toDate(notBefore), toDate(notAfter), subject, reqPublicKey);

			certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
					createSubjectKeyIdentifier(reqPublicKey));
			certificateBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

			certificateBuilder.addExtension(Extension.keyUsage, true, new org.bouncycastle.asn1.x509.KeyUsage(
					keyUsage.stream().mapToInt(KeyUsage::getValue).reduce((a, b) -> a | b).getAsInt()));

			certificateBuilder.addExtension(Extension.extendedKeyUsage, false,
					new org.bouncycastle.asn1.x509.ExtendedKeyUsage(extendedKeyUsage.stream()
							.map(ExtendedKeyUsage::toKeyPurposeId).toArray(KeyPurposeId[]::new)));

			if (subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty())
			{
				GeneralNames names = new GeneralNames(subjectAlternativeNames.toArray(GeneralName[]::new));
				certificateBuilder.addExtension(Extension.subjectAlternativeName, false, names);
			}

			certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyIdentifier());

			if (!crlDistributionPoints.isEmpty())
				certificateBuilder.addExtension(Extension.cRLDistributionPoints, false,
						new CRLDistPoint(crlDistributionPoints.stream().map(this::toDistributionPoint)
								.toArray(DistributionPoint[]::new)));

			ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());
			X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
			X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);

			return certificate;
		}
		catch (NoSuchAlgorithmException | OperatorCreationException | CertificateException | IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	private DistributionPoint toDistributionPoint(URL url)
	{
		return new DistributionPoint(
				new DistributionPointName(
						new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, url.toString()))),
				null, null);
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
	 */
	public static List<GeneralName> getSubjectAlternativeNames(JcaPKCS10CertificationRequest request)
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

	private static ASN1Primitive toDERObject(DEROctetString o)
	{
		byte[] data = o.getOctets();
		ByteArrayInputStream inStream = new ByteArrayInputStream(data);
		try (ASN1InputStream asnInputStream = new ASN1InputStream(inStream))
		{
			return asnInputStream.readObject();
		}
		catch (IOException e)
		{
			throw new RuntimeException(e);
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

	/**
	 * @param certificate
	 *            not <code>null</code>
	 * @param revocationDate
	 *            not <code>null</code>
	 * @param reason
	 *            not <code>null</code>
	 * @return new {@link RevocationEntry}
	 */
	public static RevocationEntry createRevocationEntry(X509Certificate certificate, LocalDateTime revocationDate,
			RevocationReason reason)
	{
		Objects.requireNonNull(certificate, "certificate");
		Objects.requireNonNull(revocationDate, "revocationDate");
		Objects.requireNonNull(reason, "reason");

		return new RevocationEntry(certificate, revocationDate, reason);
	}

	/**
	 * @return empty revocation list with next update in {@link #SEVEN_DAYS}
	 */
	public X509CRL createEmptyRevocationList()
	{
		return createEmptyRevocationList(SEVEN_DAYS);
	}

	/**
	 * @param nextUpdateIn
	 *            not <code>null</code>
	 * @return empty revocation list
	 */
	public X509CRL createEmptyRevocationList(TemporalAmount nextUpdateIn)
	{
		return createRevocationList(List.of(), nextUpdateIn);
	}

	/**
	 * @param entries
	 *            not <code>null</code>
	 * @return signed revocation list with next update in {@link #SEVEN_DAYS}
	 * @see #createRevocationEntry(X509Certificate, LocalDateTime, RevocationReason)
	 */
	public X509CRL createRevocationList(List<RevocationEntry> entries)
	{
		return createRevocationList(entries, SEVEN_DAYS);
	}

	/**
	 * @param entries
	 *            not <code>null</code>
	 * @param nextUpdateIn
	 *            not <code>null</code>
	 * @return signed revocation list
	 * @see #createRevocationEntry(X509Certificate, LocalDateTime, RevocationReason)
	 */
	public X509CRL createRevocationList(List<RevocationEntry> entries, TemporalAmount nextUpdateIn)
	{
		Objects.requireNonNull(entries, "entries");
		Objects.requireNonNull(nextUpdateIn, "nextUpdateIn");

		LocalDateTime now = LocalDateTime.now();
		LocalDateTime nextUpdate = now.plus(nextUpdateIn);

		X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(caCertificate.getSubjectX500Principal(), toDate(now));
		crlBuilder.setNextUpdate(toDate(nextUpdate));

		try
		{
			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(caCertificate));

			ExtensionsGenerator generator = new ExtensionsGenerator();
			entries.forEach(e -> crlBuilder.addCRLEntry(e.certificate().getSerialNumber(), toDate(e.revocationDate()),
					generateReasonCodeExtensions(generator, e)));

			JcaX509CRLConverter converter = new JcaX509CRLConverter();
			return converter.getCRL(crlBuilder.build(contentSignerBuilder.build(keyPair.getPrivate())));
		}
		catch (CertificateEncodingException | NoSuchAlgorithmException | CertIOException | CRLException
				| OperatorCreationException e)
		{
			throw new RuntimeException(e);
		}
	}

	private Extensions generateReasonCodeExtensions(ExtensionsGenerator generator, RevocationEntry entry)
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

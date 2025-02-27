package de.hsheilbronn.mi.utils.crypto.ca;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class CertificationRequestBuilder
{
	private final JcaContentSignerBuilder contentSignerBuilder;
	private final KeyPairGeneratorFactory keyPairGeneratorFactory;

	public CertificationRequestBuilder(JcaContentSignerBuilder contentSignerBuilder,
			KeyPairGeneratorFactory keyPairGeneratorFactory)
	{
		this.contentSignerBuilder = contentSignerBuilder;
		this.keyPairGeneratorFactory = keyPairGeneratorFactory;
	}

	public KeyPairGenerator getKeyPairGenerator()
	{
		return keyPairGeneratorFactory.initialize();
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
	 *            may be <code>null</code>
	 * @return X500 Name with non <code>null</code>, non blank elements
	 */
	public X500Name createName(String countryCode, String state, String locality, String organization,
			String organizationalUnit, String commonName)
	{
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
		if (commonName != null && !commonName.isBlank())
			subjectBuilder.addRDN(BCStyle.CN, commonName);

		return subjectBuilder.build();
	}

	/**
	 * @param keyPair
	 *            not <code>null</code>
	 * @param subject
	 *            not <code>null</code>
	 * @return certification request
	 */
	public JcaPKCS10CertificationRequest createCertificationRequest(KeyPair keyPair, X500Name subject)
	{
		return createCertificationRequest(keyPair, subject, null);
	}

	/**
	 * @param keyPair
	 *            not <code>null</code>
	 * @param subject
	 *            not <code>null</code>
	 * @param email
	 *            may be <code>null</code>
	 * @return certification request
	 */
	public JcaPKCS10CertificationRequest createCertificationRequest(KeyPair keyPair, X500Name subject, String email)
	{
		return createCertificationRequest(keyPair, subject, email, null);
	}

	/**
	 * Adds common-name (CN) from subject as alternative DNS name if <b>dnsNames</b> is not empty and common-name not
	 * already included.
	 * 
	 * @param keyPair
	 *            not <code>null</code>
	 * @param subject
	 *            not <code>null</code>
	 * @param email
	 *            may be <code>null</code>
	 * @param dnsNames
	 *            may be <code>null</code>
	 * @return certification request
	 */
	public JcaPKCS10CertificationRequest createCertificationRequest(KeyPair keyPair, X500Name subject, String email,
			Collection<String> dnsNames)
	{
		Objects.requireNonNull(keyPair, "keyPair");
		Objects.requireNonNull(subject, "subject");

		JcaPKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
				keyPair.getPublic());

		List<GeneralName> subAltNames = new ArrayList<>();

		if (email != null && !email.isBlank())
			subAltNames.add(new GeneralName(GeneralName.rfc822Name, email));

		Stream<String> commonName = Arrays.stream(subject.getRDNs(BCStyle.CN)).filter(Objects::nonNull)
				.map(RDN::getFirst).filter(Objects::nonNull).map(AttributeTypeAndValue::getValue)
				.map(IETFUtils::valueToString);

		if (dnsNames != null && !dnsNames.isEmpty())
		{
			List<GeneralName> altNames = Stream.concat(commonName, dnsNames.stream()).distinct().sorted()
					.filter(d -> d != null && !d.isBlank()).map(d -> new GeneralName(GeneralName.dNSName, d)).toList();

			subAltNames.addAll(altNames);
		}

		if (subAltNames.size() > 0)
		{
			ASN1Encodable[] subjectAlternativeNames = new ASN1Encodable[] { Extension.subjectAlternativeName,
					newDerOctetString(new GeneralNames(subAltNames.toArray(GeneralName[]::new))) };
			DERSequence subjectAlternativeNamesExtension = new DERSequence(subjectAlternativeNames);

			ASN1Encodable[] extensions = new ASN1Encodable[] { subjectAlternativeNamesExtension };
			requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSequence(extensions));
		}

		return new JcaPKCS10CertificationRequest(
				requestBuilder.build(buildContentSigner(contentSignerBuilder, keyPair)));
	}

	private static ContentSigner buildContentSigner(JcaContentSignerBuilder contentSignerBuilder, KeyPair keyPair)
	{
		try
		{
			return contentSignerBuilder.build(keyPair.getPrivate());
		}
		catch (OperatorCreationException e)
		{
			throw new RuntimeException(e);
		}
	}

	private static DEROctetString newDerOctetString(ASN1Encodable encodable)
	{
		try
		{
			return new DEROctetString(encodable);
		}
		catch (IOException e)
		{
			throw new RuntimeException(e);
		}
	}
}

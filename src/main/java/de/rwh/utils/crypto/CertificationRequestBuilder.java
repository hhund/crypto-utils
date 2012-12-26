/**
 * 
 */
package de.rwh.utils.crypto;

import static de.rwh.utils.crypto.CertificateHelper.getContentSigner;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * @author hhund
 * 
 */
public class CertificationRequestBuilder
{
	public static KeyPair createRsaKeyPair() throws NoSuchAlgorithmException
	{
		return CertificateHelper.createRsaKeyPair();
	}

	public static X500Name createSubject(String countryCode, String state, String locality, String organization,
			String organizationalUnitName, String commonName)
	{
		X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);

		if (countryCode != null && !countryCode.isEmpty())
			subjectBuilder.addRDN(BCStyle.C, countryCode);
		if (state != null && !state.isEmpty())
			subjectBuilder.addRDN(BCStyle.ST, state);
		if (locality != null && !locality.isEmpty())
			subjectBuilder.addRDN(BCStyle.L, locality);
		if (organization != null && !organization.isEmpty())
			subjectBuilder.addRDN(BCStyle.O, organization);
		if (organizationalUnitName != null && !organizationalUnitName.isEmpty())
			subjectBuilder.addRDN(BCStyle.OU, organizationalUnitName);
		if (commonName != null && !commonName.isEmpty())
			subjectBuilder.addRDN(BCStyle.CN, commonName);

		return subjectBuilder.build();
	}

	/**
	 * @param subject
	 * @param rsaKeyPair
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @see Security#addProvider(Provider)
	 */
	public static JcaPKCS10CertificationRequest createCertificationRequest(X500Name subject, KeyPair rsaKeyPair)
			throws NoSuchAlgorithmException, IOException, OperatorCreationException, IllegalStateException
	{
		return createCertificationRequest(subject, rsaKeyPair, null);
	}

	/**
	 * @param subject
	 * @param rsaKeyPair
	 * @param email
	 * @param dnsNames
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @see Security#addProvider(Provider)
	 */
	public static JcaPKCS10CertificationRequest createCertificationRequest(X500Name subject, KeyPair rsaKeyPair,
			String email, String... dnsNames) throws NoSuchAlgorithmException, IOException, OperatorCreationException,
			IllegalStateException
	{
		JcaPKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
				rsaKeyPair.getPublic());

		List<GeneralName> subAltNames = new ArrayList<>(dnsNames.length + 1);
		if (email != null && !email.isEmpty())
			subAltNames.add(new GeneralName(GeneralName.rfc822Name, email));
		for (String dnsName : dnsNames)
			if (dnsName != null && !dnsName.isEmpty())
				subAltNames.add(new GeneralName(GeneralName.dNSName, dnsName));

		if (subAltNames.size() > 0)
			requestBuilder.addAttribute(Extension.subjectAlternativeName,
					new GeneralNames(subAltNames.toArray(new GeneralName[subAltNames.size()])));

		ContentSigner contentSigner = getContentSigner(rsaKeyPair.getPrivate());

		return new JcaPKCS10CertificationRequest(requestBuilder.build(contentSigner));
	}
}

/**
 * 
 */
package de.rwh.utils.crypto;

import static de.rwh.utils.crypto.CertificateHelper.getContentSigner;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

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
	public static void registerBouncyCastleProvider()
	{
		CertificateHelper.registerBouncyCastleProvider();
	}

	public static KeyPair createRsaKeyPair4096Bit() throws NoSuchAlgorithmException
	{
		return CertificateHelper.createRsaKeyPair4096Bit();
	}

	public static X500Name createSubject(String countryCode, String state, String locality, String organization,
			String organizationalUnit, String commonName)
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
		if (organizationalUnit != null && !organizationalUnit.isEmpty())
			subjectBuilder.addRDN(BCStyle.OU, organizationalUnit);
		if (commonName != null && !commonName.isEmpty())
			subjectBuilder.addRDN(BCStyle.CN, commonName);

		return subjectBuilder.build();
	}

	/**
	 * @param subject
	 *            not <code>null</code>
	 * @param rsaKeyPair
	 *            not <code>null</code>
	 * @return a PKCS 10 certification request
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @see CertificationRequestBuilder#registerBouncyCastleProvider()
	 */
	public static JcaPKCS10CertificationRequest createCertificationRequest(X500Name subject, KeyPair rsaKeyPair)
			throws NoSuchAlgorithmException, IOException, OperatorCreationException, IllegalStateException
	{
		return createCertificationRequest(subject, rsaKeyPair, null);
	}

	/**
	 * @param subject
	 *            not <code>null</code>
	 * @param rsaKeyPair
	 *            not <code>null</code>
	 * @param email
	 * @param dnsNames
	 *            not <code>null</code>
	 * @return a PKCS 10 certification request
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @see CertificationRequestBuilder#registerBouncyCastleProvider()
	 */
	public static JcaPKCS10CertificationRequest createCertificationRequest(X500Name subject, KeyPair rsaKeyPair,
			String email, String... dnsNames) throws NoSuchAlgorithmException, IOException, OperatorCreationException,
			IllegalStateException
	{
		return createCertificationRequest(subject, rsaKeyPair, email, Arrays.asList(dnsNames));
	}

	/**
	 * @param subject
	 *            not <code>null</code>
	 * @param rsaKeyPair
	 *            not <code>null</code>
	 * @param email
	 * @param dnsNames
	 *            not <code>null</code>
	 * @return a PKCS 10 certification request
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws IllegalStateException
	 *             if the {@link BouncyCastleProvider} is not found
	 * @see CertificationRequestBuilder#registerBouncyCastleProvider()
	 */
	public static JcaPKCS10CertificationRequest createCertificationRequest(X500Name subject, KeyPair rsaKeyPair,
			String email, Collection<String> dnsNames) throws NoSuchAlgorithmException, IOException,
			OperatorCreationException, IllegalStateException
	{
		Objects.requireNonNull(subject, "subject");
		Objects.requireNonNull(rsaKeyPair, "rsaKeyPair");
		Objects.requireNonNull(dnsNames, "dnsNames");

		JcaPKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
				rsaKeyPair.getPublic());

		List<GeneralName> subAltNames = new ArrayList<>(dnsNames.size() + 1);
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

package de.hsheilbronn.mi.utils.crypto.ca;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
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
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class CertificationRequest
{
	/**
	 * Key: RSA 3072 Bit, Signature Algorithm: SHA512WithRSA
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
	 * @return new {@link CertificationRequestBuilder}
	 */
	public static CertificationRequestBuilder builderSha256Rsa3072(String countryCode, String state, String locality,
			String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.sha256WithRsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.rsa3072();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Key: RSA 4096 Bit, Signature Algorithm: SHA256WithRSA
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
	 * @return new {@link CertificationRequestBuilder}
	 */
	public static CertificationRequestBuilder builderSha512Rsa4096(String countryCode, String state, String locality,
			String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.sha512WithRsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.rsa4096();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Key: secp384r1, Signature algorithm: SHA384withECDSA
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
	 * @return new {@link CertificationRequestBuilder}
	 */
	public static CertificationRequestBuilder builderSha384EcdsaSecp384r1(String countryCode, String state,
			String locality, String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.sha384withEcdsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.secp384r1();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Key: secp521r1, Signature algorithm: SHA512withECDSA Note: secp521r1 not widely supported by webbrowsers
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
	 * @return new {@link CertificationRequestBuilder}
	 */
	public static CertificationRequestBuilder builderSha512EcdsaSecp521r1(String countryCode, String state,
			String locality, String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.sha512withEcdsa();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.secp521r1();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Key: ed25519, Signature algorithm: Ed25519 Note: ed25519 not supported by webbrowsers
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
	 * @return new {@link CertificationRequestBuilder}
	 */
	public static CertificationRequestBuilder builderEd25519(String countryCode, String state, String locality,
			String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.ed25519();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.ed25519();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * Key: ed448, Signature algorithm: Ed448
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
	 * @return new {@link CertificationRequestBuilder}
	 */
	public static CertificationRequestBuilder builderEd448(String countryCode, String state, String locality,
			String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		JcaContentSignerBuilder contentSignerBuilder = JcaContentSignerBuilderFactory.ed448();
		KeyPairGeneratorFactory keyPairGenertorFactory = KeyPairGeneratorFactory.ed448();

		return builder(contentSignerBuilder, keyPairGenertorFactory,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * @param ca
	 *            not <code>null</code>
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
	 * @return new {@link CertificationRequestBuilder} with {@link JcaContentSignerBuilder} and
	 *         {@link KeyPairGeneratorFactory} from given <b>ca</b>
	 */
	public static CertificationRequestBuilder builder(CertificateAuthority ca, String countryCode, String state,
			String locality, String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(ca, "ca");
		Objects.requireNonNull(commonName, "commonName");

		return builder(ca.getContentSignerBuilder(), ca.getKeyPairGeneratorFactory(),
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

	/**
	 * @param ca
	 *            not <code>null</code>
	 * @param name
	 *            not <code>null</code>
	 * @return new {@link CertificationRequestBuilder} with {@link JcaContentSignerBuilder} and
	 *         {@link KeyPairGeneratorFactory} from given <b>ca</b>
	 */
	public static CertificationRequestBuilder builder(CertificateAuthority ca, X500Name name)
	{
		Objects.requireNonNull(ca, "ca");

		return builder(ca.getContentSignerBuilder(), ca.getKeyPairGeneratorFactory(), name);
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
	 * @return new {@link CertificationRequestBuilder}
	 * @see JcaContentSignerBuilderFactory
	 */
	public static CertificationRequestBuilder builder(JcaContentSignerBuilder contentSignerBuilder,
			KeyPairGeneratorFactory keyPairGenertorFactory, X500Name name)
	{
		return new CertificationRequestBuilder(contentSignerBuilder, keyPairGenertorFactory, name);
	}

	public static class CertificationRequestBuilder
	{
		private final JcaContentSignerBuilder contentSignerBuilder;
		private final KeyPairGeneratorFactory keyPairGeneratorFactory;
		private final X500Name name;

		private final List<String> dnsNames = new ArrayList<>();
		private String email;

		private CertificationRequestBuilder(JcaContentSignerBuilder contentSignerBuilder,
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
		 * @param dnsName
		 *            must not be blank, must be US_ASCII, may be <code>null</code>
		 * @return this {@link CertificationRequestBuilder}
		 * @throws IllegalArgumentException
		 *             if given <b>dnsName</b> {@link String#isBlank()} or can not be encoded with
		 *             {@link StandardCharsets#US_ASCII}
		 */
		public CertificationRequestBuilder addDnsName(String dnsName)
		{
			if (dnsName != null && (dnsName.isBlank() || !StandardCharsets.US_ASCII.newEncoder().canEncode(dnsName)))
				throw new IllegalArgumentException("dnsName blank or contains non US_ASCII characters");

			dnsNames.add(dnsName);

			return this;
		}

		/**
		 * Clears dnsNames property and sets all from the given collection.
		 * 
		 * @param dnsNames
		 *            ignores <code>null</code> values
		 * @return this {@link CertificationRequestBuilder}
		 * @throws IllegalArgumentException
		 *             if collection contains {@link String#isBlank()} values or values that can not be encoded with
		 *             {@link StandardCharsets#US_ASCII}
		 */
		public CertificationRequestBuilder setDnsNames(String... dnsNames)
		{
			setDnsNames(List.of(dnsNames));

			return this;
		}

		/**
		 * Clears dnsNames property and sets all from the given collection.
		 * 
		 * @param dnsNames
		 *            not <code>null</code>, ignores <code>null</code> values
		 * @return this {@link CertificationRequestBuilder}
		 * @throws IllegalArgumentException
		 *             if collection contains {@link String#isBlank()} values or values that can not be encoded with
		 *             {@link StandardCharsets#US_ASCII}
		 */
		public CertificationRequestBuilder setDnsNames(Collection<String> dnsNames)
		{
			Objects.requireNonNull(dnsNames, "dnsNames");
			
			if (dnsNames.stream().filter(Objects::nonNull)
					.anyMatch(n -> n.isBlank() || !StandardCharsets.US_ASCII.newEncoder().canEncode(n)))
				throw new IllegalArgumentException("dnsNames contains blank or non US_ASCII characters value");

			if (dnsNames != null)
			{
				this.dnsNames.clear();
				this.dnsNames.addAll(dnsNames.stream().filter(Objects::nonNull).toList());
			}

			return this;
		}

		/**
		 * @param email
		 *            must not be blank, must be US_ASCII, may be <code>null</code>
		 * @return this {@link CertificationRequestBuilder}
		 * @throws IllegalArgumentException
		 *             if given <b>email</b> {@link String#isBlank()} or can not be encoded with
		 *             {@link StandardCharsets#US_ASCII}
		 */
		public CertificationRequestBuilder setEmail(String email)
		{
			if (email != null && (email.isBlank() || !StandardCharsets.US_ASCII.newEncoder().canEncode(email)))
				throw new IllegalArgumentException("email blank or contains non US_ASCII characters");

			this.email = email;

			return this;
		}

		public CertificationRequest build()
		{
			KeyPair keyPair = keyPairGeneratorFactory.initialize().generateKeyPair();
			JcaPKCS10CertificationRequest request = toJcaPKCS10CertificationRequest(contentSignerBuilder, keyPair, name,
					email, dnsNames);

			return new CertificationRequest(request, keyPair.getPrivate());
		}

		private static JcaPKCS10CertificationRequest toJcaPKCS10CertificationRequest(
				JcaContentSignerBuilder contentSignerBuilder, KeyPair keyPair, X500Name subject, String email,
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
						.filter(d -> d != null && !d.isBlank()).map(d -> new GeneralName(GeneralName.dNSName, d))
						.toList();

				subAltNames.addAll(altNames);
			}

			try
			{
				if (subAltNames.size() > 0)
				{
					ASN1Encodable[] subjectAlternativeNames = new ASN1Encodable[] { Extension.subjectAlternativeName,
							new DEROctetString(new GeneralNames(subAltNames.toArray(GeneralName[]::new))) };
					DERSequence subjectAlternativeNamesExtension = new DERSequence(subjectAlternativeNames);

					ASN1Encodable[] extensions = new ASN1Encodable[] { subjectAlternativeNamesExtension };
					requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
							new DERSequence(extensions));
				}

				return new JcaPKCS10CertificationRequest(
						requestBuilder.build(contentSignerBuilder.build(keyPair.getPrivate())));
			}
			catch (OperatorCreationException | IOException e)
			{
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * @param request
	 *            not <code>null</code>
	 * @return {@link CertificationRequest} from the given {@link JcaPKCS10CertificationRequest}
	 * @throws RuntimeException
	 *             if public key extraction fails with {@link InvalidKeyException} or {@link NoSuchAlgorithmException}
	 */
	public CertificationRequest fromJcaPKCS10CertificationRequest(JcaPKCS10CertificationRequest request)
	{
		Objects.requireNonNull(request, "request");

		return new CertificationRequest(request, null);
	}

	private final PrivateKey privateKey;
	private final JcaPKCS10CertificationRequest request;

	private CertificationRequest(JcaPKCS10CertificationRequest request, PrivateKey privateKey)
	{
		Objects.requireNonNull(request, "request");
		Objects.requireNonNull(request.getSubject(), "request.subject");
		Objects.requireNonNull(getPublicKey(request), "request.publicKey");
		// privateKey may be null

		this.request = request;
		this.privateKey = privateKey;
	}

	private PublicKey getPublicKey(JcaPKCS10CertificationRequest request)
	{
		try
		{
			return request.getPublicKey();
		}
		catch (InvalidKeyException | NoSuchAlgorithmException e)
		{
			throw new RuntimeException(e);
		}
	}

	public JcaPKCS10CertificationRequest getRequest()
	{
		return request;
	}

	public X500Name getSubject()
	{
		return request.getSubject();
	}

	public Optional<PrivateKey> getPrivateKey()
	{
		return Optional.ofNullable(privateKey);
	}

	/**
	 * @return {@link PublicKey} from the {@link JcaPKCS10CertificationRequest}
	 * @throws RuntimeException
	 *             if public key extraction fails with {@link InvalidKeyException} or {@link NoSuchAlgorithmException}
	 */
	public PublicKey getPublicKey()
	{
		return getPublicKey(request);
	}
}

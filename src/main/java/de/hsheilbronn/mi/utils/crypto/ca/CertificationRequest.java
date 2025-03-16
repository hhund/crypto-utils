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
import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairValidator;

public class CertificationRequest
{
	/**
	 * @param contentSignerBuilder
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
	 *            may be <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPair}
	 */
	public static CertificationRequestBuilderKeyPair builder(JcaContentSignerBuilder contentSignerBuilder,
			String countryCode, String state, String locality, String organization, String organizationalUnit,
			String commonName)
	{
		return builder(contentSignerBuilder,
				createName(countryCode, state, locality, organization, organizationalUnit, commonName));
	}

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
	 *            may be <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPairGenerator}
	 */
	public static CertificationRequestBuilderKeyPairGenerator builderSha256Rsa3072(String countryCode, String state,
			String locality, String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(commonName, "commonName");

		return builder(JcaContentSignerBuilderFactory.sha256WithRsa(),
				createName(countryCode, state, locality, organization, organizationalUnit, commonName),
				KeyPairGeneratorFactory.rsa3072());
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
	 *            may be <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPairGenerator}
	 */
	public static CertificationRequestBuilderKeyPairGenerator builderSha512Rsa4096(String countryCode, String state,
			String locality, String organization, String organizationalUnit, String commonName)
	{
		return builder(JcaContentSignerBuilderFactory.sha512WithRsa(),
				createName(countryCode, state, locality, organization, organizationalUnit, commonName),
				KeyPairGeneratorFactory.rsa4096());
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
	 *            may be <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPairGenerator}
	 */
	public static CertificationRequestBuilderKeyPairGenerator builderSha384EcdsaSecp384r1(String countryCode,
			String state, String locality, String organization, String organizationalUnit, String commonName)
	{
		return builder(JcaContentSignerBuilderFactory.sha384withEcdsa(),
				createName(countryCode, state, locality, organization, organizationalUnit, commonName),
				KeyPairGeneratorFactory.secp384r1());
	}

	/**
	 * Key: secp521r1, Signature algorithm: SHA512withECDSA Note: secp521r1 not widely supported by web browsers
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
	 *            may be <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPairGenerator}
	 */
	public static CertificationRequestBuilderKeyPairGenerator builderSha512EcdsaSecp521r1(String countryCode,
			String state, String locality, String organization, String organizationalUnit, String commonName)
	{
		return builder(JcaContentSignerBuilderFactory.sha512withEcdsa(),
				createName(countryCode, state, locality, organization, organizationalUnit, commonName),
				KeyPairGeneratorFactory.secp521r1());
	}

	/**
	 * Key: ed25519, Signature algorithm: Ed25519 Note: ed25519 not supported by web browsers
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
	 *            may be <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPairGenerator}
	 */
	public static CertificationRequestBuilderKeyPairGenerator builderEd25519(String countryCode, String state,
			String locality, String organization, String organizationalUnit, String commonName)
	{
		return builder(JcaContentSignerBuilderFactory.ed25519(),
				createName(countryCode, state, locality, organization, organizationalUnit, commonName),
				KeyPairGeneratorFactory.ed25519());
	}

	/**
	 * Key: ed448, Signature algorithm: Ed448 Note: ed448 not supported by web browsers
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
	 *            may be <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPairGenerator}
	 */
	public static CertificationRequestBuilderKeyPairGenerator builderEd448(String countryCode, String state,
			String locality, String organization, String organizationalUnit, String commonName)
	{
		return builder(JcaContentSignerBuilderFactory.ed448(),
				createName(countryCode, state, locality, organization, organizationalUnit, commonName),
				KeyPairGeneratorFactory.ed448());
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
	 *            may be <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPairGenerator} with {@link JcaContentSignerBuilder} and
	 *         {@link KeyPairGeneratorFactory} from given <b>ca</b>
	 */
	public static CertificationRequestBuilderKeyPairGenerator builder(CertificateAuthority ca, String countryCode,
			String state, String locality, String organization, String organizationalUnit, String commonName)
	{
		Objects.requireNonNull(ca, "ca");

		return builder(ca, createName(countryCode, state, locality, organization, organizationalUnit, commonName));
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
	public static X500Name createName(String countryCode, String state, String locality, String organization,
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
	 * @param contentSignerBuilder
	 *            not <code>null</code>
	 * @param name
	 *            not <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPair}
	 */
	public static CertificationRequestBuilderKeyPair builder(JcaContentSignerBuilder contentSignerBuilder,
			X500Name name)
	{
		Objects.requireNonNull(contentSignerBuilder, "contentSignerBuilder");
		Objects.requireNonNull(name, "name");

		return new CertificationRequestBuilderKeyPair(contentSignerBuilder, name);
	}

	/**
	 * @param ca
	 *            not <code>null</code>
	 * @param name
	 *            not <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPairGenerator} with {@link JcaContentSignerBuilder} and
	 *         {@link KeyPairGeneratorFactory} from given <b>ca</b>
	 */
	public static CertificationRequestBuilderKeyPairGenerator builder(CertificateAuthority ca, X500Name name)
	{
		Objects.requireNonNull(ca, "ca");
		Objects.requireNonNull(name, "name");

		return builder(ca.getContentSignerBuilder(), name, ca.getKeyPairGeneratorFactory());
	}

	/**
	 * @param contentSignerBuilder
	 *            not <code>null</code>
	 * @param name
	 *            not <code>null</code>
	 * @param keyPairGenertorFactory
	 *            not <code>null</code>
	 * @return new {@link CertificationRequestBuilderKeyPairGenerator}
	 * @see JcaContentSignerBuilderFactory
	 */
	public static CertificationRequestBuilderKeyPairGenerator builder(JcaContentSignerBuilder contentSignerBuilder,
			X500Name name, KeyPairGeneratorFactory keyPairGenertorFactory)
	{
		Objects.requireNonNull(contentSignerBuilder, "contentSignerBuilder");
		Objects.requireNonNull(name, "name");
		Objects.requireNonNull(keyPairGenertorFactory, "keyPairGenertorFactory");

		return new CertificationRequestBuilderKeyPairGenerator(contentSignerBuilder, name, keyPairGenertorFactory);
	}

	public static class CertificationRequestBuilderKeyPairGenerator
	{
		private final JcaContentSignerBuilder contentSignerBuilder;
		private final X500Name name;
		private final KeyPairGeneratorFactory keyPairGenertorFactory;

		private CertificationRequestBuilderKeyPairGenerator(JcaContentSignerBuilder contentSignerBuilder, X500Name name,
				KeyPairGeneratorFactory keyPairGenertorFactory)
		{
			Objects.requireNonNull(contentSignerBuilder, "contentSignerBuilder");
			Objects.requireNonNull(name, "name");
			Objects.requireNonNull(keyPairGenertorFactory, "keyPairGenertorFactory");

			this.contentSignerBuilder = contentSignerBuilder;
			this.name = name;
			this.keyPairGenertorFactory = keyPairGenertorFactory;
		}

		public CertificationRequestBuilder generateKeyPair()
		{
			return new CertificationRequestBuilder(contentSignerBuilder, name,
					keyPairGenertorFactory.initialize().generateKeyPair());
		}
	}

	public static class CertificationRequestBuilderKeyPair
	{
		private final JcaContentSignerBuilder contentSignerBuilder;
		private final X500Name name;

		private CertificationRequestBuilderKeyPair(JcaContentSignerBuilder contentSignerBuilder, X500Name name)
		{
			this.contentSignerBuilder = contentSignerBuilder;
			this.name = name;
		}

		public CertificationRequestBuilder forKeyPair(KeyPair keyPair)
		{
			Objects.requireNonNull(keyPair, "keyPair");

			return new CertificationRequestBuilder(contentSignerBuilder, name, keyPair);
		}
	}

	public static class CertificationRequestBuilder
	{
		private final JcaContentSignerBuilder contentSignerBuilder;
		private final X500Name name;
		private final KeyPair keyPair;

		private final List<String> dnsNames = new ArrayList<>();
		private String email;

		private CertificationRequestBuilder(JcaContentSignerBuilder contentSignerBuilder, X500Name name,
				KeyPair keyPair)
		{
			Objects.requireNonNull(contentSignerBuilder, "contentSignerBuilder");
			Objects.requireNonNull(name, "name");
			Objects.requireNonNull(keyPair, "keyPair");

			this.contentSignerBuilder = contentSignerBuilder;
			this.name = name;
			this.keyPair = keyPair;
		}

		public KeyPair getKeyPair()
		{
			return keyPair;
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

		public CertificationRequestAndPrivateKey signRequest()
		{
			JcaPKCS10CertificationRequest request = toJcaPKCS10CertificationRequest(contentSignerBuilder, keyPair, name,
					email, dnsNames);

			return new CertificationRequestAndPrivateKey(request, keyPair.getPrivate());
		}

		private JcaPKCS10CertificationRequest toJcaPKCS10CertificationRequest(
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
	public static CertificationRequest of(JcaPKCS10CertificationRequest request)
	{
		Objects.requireNonNull(request, "request");

		return new CertificationRequest(request);
	}

	/**
	 * Does not verify if the given <b>privateKey</b> matches the public-key from the <b>request</b>.
	 * 
	 * @param request
	 *            not <code>null</code>
	 * @param privateKey
	 *            may be <code>null</code>
	 * @return {@link CertificationRequestAndPrivateKey} from the given {@link JcaPKCS10CertificationRequest}
	 * @throws RuntimeException
	 *             if public key extraction fails with {@link InvalidKeyException} or {@link NoSuchAlgorithmException}
	 * @see KeyPairValidator#matches(PrivateKey, PublicKey)
	 */
	public static CertificationRequestAndPrivateKey of(JcaPKCS10CertificationRequest request, PrivateKey privateKey)
	{
		Objects.requireNonNull(request, "request");

		return new CertificationRequestAndPrivateKey(request, privateKey);
	}

	/**
	 * Does not verify if the given <b>privateKey</b> matches the public-key from the <b>request</b>.
	 * 
	 * @param request
	 *            not <code>null</code>, no privateKey
	 * @param privateKey
	 *            may be <code>null</code>
	 * @return {@link CertificationRequestAndPrivateKey} from the given {@link JcaPKCS10CertificationRequest}
	 * @throws RuntimeException
	 *             if public key extraction fails with {@link InvalidKeyException} or {@link NoSuchAlgorithmException}
	 * @see KeyPairValidator#matches(PrivateKey, PublicKey)
	 */
	public static CertificationRequestAndPrivateKey of(CertificationRequest request, PrivateKey privateKey)
	{
		Objects.requireNonNull(request, "request");
		return new CertificationRequestAndPrivateKey(request.request, privateKey);
	}

	public static final class CertificationRequestAndPrivateKey extends CertificationRequest
	{
		private final PrivateKey privateKey;

		private CertificationRequestAndPrivateKey(JcaPKCS10CertificationRequest request, PrivateKey privateKey)
		{
			super(request);

			this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
		}

		/**
		 * @return {@link Optional#isEmpty()} if created from {@link JcaPKCS10CertificationRequest} without
		 *         {@link PrivateKey}
		 */
		public PrivateKey getPrivateKey()
		{
			return privateKey;
		}

		/**
		 * @return {@link KeyPair}.privateKey may be <code>null</code>
		 */
		public KeyPair getKeyPair()
		{
			return new KeyPair(getPublicKey(), getPrivateKey());
		}
	}

	private final JcaPKCS10CertificationRequest request;

	protected CertificationRequest(JcaPKCS10CertificationRequest request)
	{
		Objects.requireNonNull(request, "request");
		Objects.requireNonNull(request.getSubject(), "request.subject");
		Objects.requireNonNull(getPublicKey(request), "request.publicKey");

		this.request = request;
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

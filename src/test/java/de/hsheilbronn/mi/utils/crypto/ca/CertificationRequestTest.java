package de.hsheilbronn.mi.utils.crypto.ca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest.CertificationRequestBuilder;

public class CertificationRequestTest
{
	private static final String countryCode = "Test Country", state = "Test State", locality = "Test Locality",
			organization = "Test Organization", organizationalUnit = "Test Orgaizational Unit",
			commonName = "test.common.name", email = "test@mail.com", dnsName1 = "foo.test", dnsName2 = "bar.test";

	@ParameterizedTest
	@MethodSource("forBuildRequest")
	void buildRequest(CertificationRequestBuilder builder) throws Exception
	{
		CertificationRequest request = builder.setEmail(email).addDnsName(dnsName1).addDnsName(dnsName2).build();

		assertNotNull(request);
		assertNotNull(request.getPrivateKey());
		assertNotNull(request.getPublicKey());
		assertNotNull(request.getRequest());
		assertNotNull(request.getSubject());

		List<GeneralName> generalNames = CertificateAuthority.getSubjectAlternativeNames(request.getRequest());
		assertNotNull(generalNames);
		assertEquals(4, generalNames.size());

		assertEquals(3, generalNames.stream().filter(n -> n.getTagNo() == GeneralName.dNSName).count());
		assertEquals(1, generalNames.stream().filter(n -> n.getTagNo() == GeneralName.rfc822Name).count());

		List<String> names = generalNames.stream().map(this::generalNameToString).toList();
		assertEquals(4, names.size());
		assertTrue(names.contains(email));
		assertTrue(names.contains(commonName));
		assertTrue(names.contains(dnsName1));
		assertTrue(names.contains(dnsName2));

		assertSubjectPropertyEquals(BCStyle.C, countryCode, request.getSubject());
		assertSubjectPropertyEquals(BCStyle.ST, state, request.getSubject());
		assertSubjectPropertyEquals(BCStyle.L, locality, request.getSubject());
		assertSubjectPropertyEquals(BCStyle.O, organization, request.getSubject());
		assertSubjectPropertyEquals(BCStyle.OU, organizationalUnit, request.getSubject());
		assertSubjectPropertyEquals(BCStyle.CN, commonName, request.getSubject());
	}

	private String generalNameToString(GeneralName generalName)
	{
		DLTaggedObject name = (DLTaggedObject) generalName.getName();
		DEROctetString baseObject = (DEROctetString) name.getBaseObject();
		return new String(baseObject.getOctets(), StandardCharsets.US_ASCII);
	}

	private void assertSubjectPropertyEquals(ASN1ObjectIdentifier propertyId, String expected, X500Name subject)
	{
		RDN[] rdNs = subject.getRDNs(propertyId);
		assertNotNull(rdNs);
		assertEquals(1, rdNs.length);

		String actual = IETFUtils.valueToString(rdNs[0].getFirst().getValue());
		assertEquals(expected, actual);
	}

	private static Stream<Arguments> forBuildRequest()
	{
		return Stream.of(
				Arguments.of(CertificationRequest.builderEd25519(countryCode, state, locality, organization,
						organizationalUnit, commonName)),
				Arguments.of(CertificationRequest.builderEd448(countryCode, state, locality, organization,
						organizationalUnit, commonName)),
				Arguments.of(CertificationRequest.builderSha256Rsa3072(countryCode, state, locality, organization,
						organizationalUnit, commonName)),
				Arguments.of(CertificationRequest.builderSha384EcdsaSecp384r1(countryCode, state, locality,
						organization, organizationalUnit, commonName)),
				Arguments.of(
						CertificationRequest.builderSha512EcdsaSecp521r1(countryCode, state, locality, organization,
								organizationalUnit, commonName),
						Arguments.of(CertificationRequest.builderSha512Rsa4096(countryCode, state, locality,
								organization, organizationalUnit, commonName))));
	}
}

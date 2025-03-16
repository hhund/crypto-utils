package de.hsheilbronn.mi.utils.crypto.keystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority;
import de.hsheilbronn.mi.utils.crypto.cert.CertificateFormatter.SubjectFormat;
import de.hsheilbronn.mi.utils.crypto.io.PemReader;

public class KeyStoreFormatterTest
{
	@Test
	void getSubjectsFromCertificates() throws Exception
	{
		List<X509Certificate> certificates = PemReader.readCertificates(Paths.get("src/test/resources/dfn_chain.pem"));
		KeyStore keyStore = KeyStoreCreator.jksForTrustedCertificates(certificates);

		Map<String, String> subjects = KeyStoreFormatter.getSubjectsFromCertificates(keyStore, SubjectFormat.RFC2253);
		assertNotNull(subjects);
		assertEquals(3, subjects.size());

		assertEquals(
				"CN=T-TeleSec GlobalRoot Class 2,OU=T-Systems Trust Center,O=T-Systems Enterprise Services GmbH,C=DE",
				subjects.get(
						"cn=t-telesec globalroot class 2,ou=t-systems trust center,o=t-systems enterprise services gmbh,c=de"));
		assertEquals(
				"CN=DFN-Verein Global Issuing CA,OU=DFN-PKI,O=Verein zur Foerderung eines Deutschen Forschungsnetzes e. V.,C=DE",
				subjects.get(
						"cn=dfn-verein global issuing ca,ou=dfn-pki,o=verein zur foerderung eines deutschen forschungsnetzes e. v.,c=de"));
		assertEquals(
				"CN=DFN-Verein Certification Authority 2,OU=DFN-PKI,O=Verein zur Foerderung eines Deutschen Forschungsnetzes e. V.,C=DE",
				subjects.get(
						"cn=dfn-verein certification authority 2,ou=dfn-pki,o=verein zur foerderung eines deutschen forschungsnetzes e. v.,c=de"));

		Map<String, List<String>> chains = KeyStoreFormatter.getSubjectsFromCertificateChains(keyStore,
				SubjectFormat.RFC2253);
		assertTrue(chains.isEmpty());
	}

	@Test
	void getSubjectsFromCertificateChains() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority
				.builderSha384EcdsaSecp384r1("DE", null, null, null, null, "JUnit Test CA").build();
		KeyStore keyStore = KeyStoreCreator.jksForPrivateKeyAndCertificateChain(ca.getKeyPair().getPrivate(),
				"password".toCharArray(), ca.getCertificate());

		Map<String, List<String>> subjects = KeyStoreFormatter.getSubjectsFromCertificateChains(keyStore,
				SubjectFormat.RFC1779);
		assertNotNull(subjects);
		assertEquals(1, subjects.size());
		assertEquals(1, subjects.get("cn=junit test ca,c=de").size());
		assertEquals("CN=JUnit Test CA, C=DE", subjects.get("cn=junit test ca,c=de").get(0));
	}
}

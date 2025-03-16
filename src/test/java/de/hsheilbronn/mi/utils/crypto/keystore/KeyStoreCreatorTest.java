package de.hsheilbronn.mi.utils.crypto.keystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest.CertificationRequestAndPrivateKey;
import de.hsheilbronn.mi.utils.crypto.io.PemReader;
import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class KeyStoreCreatorTest
{
	@FunctionalInterface
	private static interface TriFunction<A, B, C, R>
	{
		R apply(A a, B b, C c);
	}

	private static Stream<Arguments> forTrustedCertificatesArguments()
	{
		Function<Collection<X509Certificate>, KeyStore> jksCollection = KeyStoreCreator::jksForTrustedCertificates;
		Function<X509Certificate[], KeyStore> jksArray = KeyStoreCreator::jksForTrustedCertificates;
		Function<Collection<X509Certificate>, KeyStore> pkcs12Collection = KeyStoreCreator::pkcs12ForTrustedCertificates;
		Function<X509Certificate[], KeyStore> pkcs12Array = KeyStoreCreator::pkcs12ForTrustedCertificates;

		return Stream.of(Arguments.of(jksCollection, jksArray), Arguments.of(pkcs12Collection, pkcs12Array));
	}

	@ParameterizedTest
	@MethodSource("forTrustedCertificatesArguments")
	void forTrustedCertificatesNull(Function<Collection<X509Certificate>, KeyStore> forCollection,
			Function<X509Certificate[], KeyStore> forArray) throws Exception
	{
		assertThrows(NullPointerException.class, () -> forCollection.apply((Collection<X509Certificate>) null));
		assertThrows(IllegalArgumentException.class, () -> forCollection.apply(List.<X509Certificate> of()));
		assertThrows(NullPointerException.class, () -> forArray.apply((X509Certificate[]) null));
		assertThrows(IllegalArgumentException.class, () -> forArray.apply(new X509Certificate[0]));
	}

	@ParameterizedTest
	@MethodSource("forTrustedCertificatesArguments")
	void forTrustedCertificates(Function<Collection<X509Certificate>, KeyStore> forCollection,
			Function<X509Certificate[], KeyStore> forArray) throws Exception
	{
		List<X509Certificate> certificates = PemReader.readCertificates(Paths.get("src/test/resources/dfn_chain.pem"));
		assertNotNull(certificates);
		assertEquals(3, certificates.size());

		KeyStore keyStoreFromCollection = forCollection.apply(certificates);
		assertNotNull(keyStoreFromCollection);
		assertEquals(3, keyStoreFromCollection.size());

		KeyStore keyStoreFromArray = forArray.apply(certificates.toArray(X509Certificate[]::new));
		assertNotNull(keyStoreFromArray);
		assertEquals(3, keyStoreFromArray.size());

		assertExists(keyStoreFromCollection, keyStoreFromArray,
				"cn=t-telesec globalroot class 2,ou=t-systems trust center,o=t-systems enterprise services gmbh,c=de");
		assertExists(keyStoreFromCollection, keyStoreFromArray,
				"cn=dfn-verein global issuing ca,ou=dfn-pki,o=verein zur foerderung eines deutschen forschungsnetzes e. v.,c=de");
		assertExists(keyStoreFromCollection, keyStoreFromArray,
				"cn=dfn-verein certification authority 2,ou=dfn-pki,o=verein zur foerderung eines deutschen forschungsnetzes e. v.,c=de");
	}

	void assertExists(KeyStore keyStore1, KeyStore keyStore2, String alias) throws KeyStoreException
	{
		Certificate cert1 = keyStore1.getCertificate(alias);
		assertNotNull(cert1);
		assertInstanceOf(X509Certificate.class, cert1);

		Certificate cert2 = keyStore2.getCertificate(alias);
		assertNotNull(cert2);
		assertInstanceOf(X509Certificate.class, cert2);
	}

	private static Stream<Arguments> forPrivateKeyAndCertificateChainArguments()
	{
		TriFunction<PrivateKey, char[], Collection<X509Certificate>, KeyStore> jksCollection = KeyStoreCreator::jksForPrivateKeyAndCertificateChain;
		TriFunction<PrivateKey, char[], X509Certificate[], KeyStore> jksArray = KeyStoreCreator::jksForPrivateKeyAndCertificateChain;
		TriFunction<PrivateKey, char[], Collection<X509Certificate>, KeyStore> pkcs12Collection = KeyStoreCreator::pkcs12ForPrivateKeyAndCertificateChain;
		TriFunction<PrivateKey, char[], X509Certificate[], KeyStore> pkcs12Array = KeyStoreCreator::pkcs12ForPrivateKeyAndCertificateChain;

		return Stream.of(Arguments.of(jksCollection, jksArray), Arguments.of(pkcs12Collection, pkcs12Array));
	}

	@ParameterizedTest
	@MethodSource("forPrivateKeyAndCertificateChainArguments")
	void forPrivateKeyAndCertificateChainNull(
			TriFunction<PrivateKey, char[], Collection<X509Certificate>, KeyStore> forCollection,
			TriFunction<PrivateKey, char[], X509Certificate[], KeyStore> forArray) throws Exception
	{
		final PrivateKey key = KeyPairGeneratorFactory.rsa1024().initialize().generateKeyPair().getPrivate();
		final char[] password = "password".toCharArray();

		assertThrows(NullPointerException.class, () -> forCollection.apply(null, null, null));
		assertThrows(NullPointerException.class, () -> forCollection.apply(key, null, null));
		assertThrows(NullPointerException.class, () -> forCollection.apply(key, password, null));

		assertThrows(IllegalArgumentException.class, () -> forCollection.apply(key, password, List.of()));

		assertThrows(NullPointerException.class, () -> forArray.apply(null, null, null));
		assertThrows(NullPointerException.class, () -> forArray.apply(key, null, null));
		assertThrows(NullPointerException.class, () -> forArray.apply(key, password, null));

		assertThrows(IllegalArgumentException.class, () -> forArray.apply(key, password, new X509Certificate[0]));
	}

	@ParameterizedTest
	@MethodSource("forPrivateKeyAndCertificateChainArguments")
	void forPrivateKeyAndCertificateChain(
			TriFunction<PrivateKey, char[], Collection<X509Certificate>, KeyStore> forCollection,
			TriFunction<PrivateKey, char[], X509Certificate[], KeyStore> forArray) throws Exception
	{
		final CertificateAuthority ca = CertificateAuthority
				.builderSha256Rsa3072("DE", null, null, null, null, "JUnit Test CA").build();
		final CertificationRequestAndPrivateKey req = CertificationRequest
				.builder(ca, "DE", null, null, null, null, "JUnit Test Client").generateKeyPair().signRequest();
		final X509Certificate certificate = ca.signClientCertificate(req);
		final PrivateKey key = req.getPrivateKey();
		final char[] password = "password".toCharArray();

		KeyStore keyStoreC = forCollection.apply(key, password, List.of(certificate, ca.getCertificate()));
		assertKeyStoreOk(List.of(certificate, ca.getCertificate()), key, password, keyStoreC);

		KeyStore keyStoreA = forArray.apply(key, password, new X509Certificate[] { certificate });
		assertKeyStoreOk(List.of(certificate), key, password, keyStoreA);
	}

	private void assertKeyStoreOk(final List<X509Certificate> certificates, final PrivateKey key, final char[] password,
			KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		assertNotNull(keyStore);
		assertEquals(1, keyStore.size());

		List<String> aliases = Collections.list(keyStore.aliases());
		assertEquals(1, aliases.size());

		Key keyFromStore = keyStore.getKey(aliases.get(0), password);
		assertNotNull(keyFromStore);
		assertEquals(key, keyFromStore);

		Certificate certificateFromStore = keyStore.getCertificate(aliases.get(0));
		assertNotNull(certificateFromStore);
		assertEquals(certificates.get(0), certificateFromStore);

		Certificate[] chain = keyStore.getCertificateChain(aliases.get(0));
		assertNotNull(chain);
		assertEquals(certificates.size(), chain.length);
		for (int i = 0; i < chain.length; i++)
			assertEquals(certificates.get(i), chain[i]);
	}
}

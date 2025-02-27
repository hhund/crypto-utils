package de.hsheilbronn.mi.utils.crypto.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority;
import de.hsheilbronn.mi.utils.crypto.keystore.KeyStoreCreator;

public class KeyStoreWriterReaderTest
{
	private static final char[] password = "password".toCharArray();

	@Test
	void writeReadPkcs12String() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderSha256Rsa3072()
				.newCa("DE", null, null, null, null, "JUnit Test CA").build();
		PrivateKey privateKey = ca.getKeyPair().getPrivate();
		X509Certificate certificate = ca.getCertificate();
		KeyStore keyStore = KeyStoreCreator.pkcs12ForPrivateKeyAndCertificateChain(privateKey, password, certificate);

		byte[] pkcs12 = KeyStoreWriter.write(keyStore, password);
		assertNotNull(pkcs12);
		assertTrue(pkcs12.length > 0);

		KeyStore readKeyStore = KeyStoreReader.readPkcs12(pkcs12, password);
		assertKeyStoreOk(certificate, privateKey, password, readKeyStore);
	}

	@Test
	void writeReadJksString() throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderSha256Rsa3072()
				.newCa("DE", null, null, null, null, "JUnit Test CA").build();
		PrivateKey privateKey = ca.getKeyPair().getPrivate();
		X509Certificate certificate = ca.getCertificate();
		KeyStore keyStore = KeyStoreCreator.jksForPrivateKeyAndCertificateChain(privateKey, password, certificate);

		byte[] jks = KeyStoreWriter.write(keyStore, password);
		assertNotNull(jks);
		assertTrue(jks.length > 0);

		KeyStore readKeyStore = KeyStoreReader.readJks(jks, password);
		assertKeyStoreOk(certificate, privateKey, password, readKeyStore);
	}

	@Test
	void writeReadPkcs12File(@TempDir Path tmp) throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderSha256Rsa3072()
				.newCa("DE", null, null, null, null, "JUnit Test CA").build();
		PrivateKey privateKey = ca.getKeyPair().getPrivate();
		X509Certificate certificate = ca.getCertificate();
		KeyStore keyStore = KeyStoreCreator.pkcs12ForPrivateKeyAndCertificateChain(privateKey, password, certificate);

		Path pkcs12 = tmp.resolve("keystore.p12");

		KeyStoreWriter.write(keyStore, password, pkcs12);

		KeyStore readKeyStore = KeyStoreReader.readPkcs12(pkcs12, password);
		assertKeyStoreOk(certificate, privateKey, password, readKeyStore);
	}

	@Test
	void writeReadJksFile(@TempDir Path tmp) throws Exception
	{
		CertificateAuthority ca = CertificateAuthority.builderSha256Rsa3072()
				.newCa("DE", null, null, null, null, "JUnit Test CA").build();
		PrivateKey privateKey = ca.getKeyPair().getPrivate();
		X509Certificate certificate = ca.getCertificate();
		KeyStore keyStore = KeyStoreCreator.jksForPrivateKeyAndCertificateChain(privateKey, password, certificate);

		Path jks = tmp.resolve("keystore.jks");

		KeyStoreWriter.write(keyStore, password, jks);

		KeyStore readKeyStore = KeyStoreReader.readJks(jks, password);
		assertKeyStoreOk(certificate, privateKey, password, readKeyStore);
	}

	private void assertKeyStoreOk(final X509Certificate certificate, final PrivateKey key, final char[] password,
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
		assertEquals(certificate, certificateFromStore);

		Certificate[] chain = keyStore.getCertificateChain(aliases.get(0));
		assertNotNull(chain);
		assertEquals(1, chain.length);
		assertEquals(certificate, chain[0]);
	}

	@Test
	void writeNull() throws Exception
	{
		KeyStore pkcs12 = KeyStore.getInstance("pkcs12");
		pkcs12.load(null, null);
		KeyStore jks = KeyStore.getInstance("jks");
		jks.load(null, null);

		assertNotNull(KeyStoreWriter.write(pkcs12, null));

		assertThrows(NullPointerException.class, () -> KeyStoreWriter.write(jks, null));
		assertThrows(NullPointerException.class, () -> KeyStoreWriter.write(null, null));

		assertThrows(NullPointerException.class, () -> KeyStoreWriter.write(null, null, (OutputStream) null));
		assertThrows(NullPointerException.class, () -> KeyStoreWriter.write(null, null, (Path) null));

		assertThrows(NullPointerException.class, () -> KeyStoreWriter.write(jks, password, (OutputStream) null));
		assertThrows(NullPointerException.class, () -> KeyStoreWriter.write(pkcs12, null, (Path) null));
		assertThrows(NullPointerException.class, () -> KeyStoreWriter.write(pkcs12, password, (Path) null));
	}

	@Test
	void readNull() throws Exception
	{
		assertThrows(NullPointerException.class, () -> KeyStoreReader.readJks((byte[]) null, null));
		assertThrows(NullPointerException.class, () -> KeyStoreReader.readJks((InputStream) null, null));
		assertThrows(NullPointerException.class, () -> KeyStoreReader.readJks((Path) null, null));

		assertThrows(NullPointerException.class, () -> KeyStoreReader.readPkcs12((byte[]) null, null));
		assertThrows(NullPointerException.class, () -> KeyStoreReader.readPkcs12((InputStream) null, null));
		assertThrows(NullPointerException.class, () -> KeyStoreReader.readPkcs12((Path) null, null));
	}
}

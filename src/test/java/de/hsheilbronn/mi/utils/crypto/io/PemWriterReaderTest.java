package de.hsheilbronn.mi.utils.crypto.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

import javax.crypto.EncryptedPrivateKeyInfo;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.ca.CertificateAuthority;
import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequestBuilder;
import de.hsheilbronn.mi.utils.crypto.io.PemWriter.PrivateKeyPemWriter;
import de.hsheilbronn.mi.utils.crypto.io.PemWriter.PrivateKeyPemWriterBuilder;
import de.hsheilbronn.mi.utils.crypto.io.PemWriter.PrivateKeyPemWriterOpenSslClassicBuilder.OpenSslClassicAlgorithm;
import de.hsheilbronn.mi.utils.crypto.io.PemWriter.PrivateKeyPemWriterPkcs8Builder.Pkcs8Algorithm;

public class PemWriterReaderTest
{
	private static final char[] PASSWORD = "password".toCharArray();
	private static final CertificateAuthority ca = CertificateAuthority.builderSha256Rsa3072()
			.newCa("DE", null, null, null, null, "JUnit Test CA").build();

	@Test
	void writeReadCertificateString() throws Exception
	{
		X509Certificate certificate = ca.getCertificate();

		String pem = PemWriter.writeCertificate(certificate, true);
		assertNotNull(pem);
		assertFalse(pem.isBlank());

		X509Certificate readCert = PemReader.readCertificate(pem);
		assertNotNull(readCert);
		assertEquals(certificate, readCert);
	}

	@Test
	void writeReadCertificateFile(@TempDir Path tmp) throws Exception
	{
		X509Certificate certificate = ca.getCertificate();

		Path certPath = tmp.resolve("cert.pem");

		PemWriter.writeCertificate(certificate, true, certPath);

		X509Certificate readCert = PemReader.readCertificate(certPath);
		assertNotNull(readCert);
		assertEquals(certificate, readCert);
	}

	@ParameterizedTest
	@MethodSource("writeReadPrivateKeyArguments")
	void writeReadPrivateKeyString(boolean encrypted, boolean pkcs8Encrypted,
			Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter> writer) throws Exception
	{
		PrivateKey privateKey = ca.getKeyPair().getPrivate();

		String pem = writer.apply(PemWriter.writePrivateKey(privateKey)).toString();
		assertNotNull(pem);
		assertFalse(pem.isBlank());

		PrivateKey readPrivateKey = PemReader.readPrivateKey(pem, PASSWORD);
		assertNotNull(readPrivateKey);
		assertEquals(privateKey, readPrivateKey);

		if (!encrypted)
		{
			PrivateKey readPrivateKeyUnencrypted = PemReader.readPrivateKey(pem);
			assertNotNull(readPrivateKeyUnencrypted);
			assertEquals(privateKey, readPrivateKeyUnencrypted);
		}

		if (pkcs8Encrypted)
		{
			EncryptedPrivateKeyInfo encryptedPrivateKey = PemReader.readPkcs8EncryptedPrivateKey(pem);
			assertNotNull(encryptedPrivateKey);
		}
	}

	@ParameterizedTest
	@MethodSource("writeReadPrivateKeyArguments")
	void writeReadPrivateKeyFile(boolean encrypted, boolean pkcs8Encrypted,
			Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter> writer, @TempDir Path tmp) throws Exception
	{
		PrivateKey privateKey = ca.getKeyPair().getPrivate();

		Path keyPath = tmp.resolve("key.pem");

		writer.apply(PemWriter.writePrivateKey(privateKey)).toFile(keyPath);

		PrivateKey readPrivateKey = PemReader.readPrivateKey(keyPath, PASSWORD);
		assertNotNull(readPrivateKey);
		assertEquals(privateKey, readPrivateKey);

		if (!encrypted)
		{
			PrivateKey readPrivateKeyUnencrypted = PemReader.readPrivateKey(keyPath);
			assertNotNull(readPrivateKeyUnencrypted);
			assertEquals(privateKey, readPrivateKeyUnencrypted);
		}

		if (pkcs8Encrypted)
		{
			EncryptedPrivateKeyInfo encryptedPrivateKey = PemReader.readPkcs8EncryptedPrivateKey(keyPath);
			assertNotNull(encryptedPrivateKey);
		}
	}

	private static Stream<Arguments> writeReadPrivateKeyArguments()
	{
		Stream<Arguments> pkcs8 = Arrays.stream(Pkcs8Algorithm.values()).map(alg -> Arguments.of(true, true,
				(Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b.asPkcs8().encrypted(PASSWORD, alg)));

		Arguments pkcs8Aes128 = Arguments.of(true, true,
				(Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b.asPkcs8().encryptedAes128(PASSWORD));
		Arguments pkcs8Aes256 = Arguments.of(true, true,
				(Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b.asPkcs8().encryptedAes256(PASSWORD));
		Arguments pkcs8TrippleDes = Arguments.of(true, true,
				(Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b.asPkcs8()
						.encryptedTrippleDes(PASSWORD));

		Arguments pkcs8NotEncrypted = Arguments.of(false, false,
				(Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b.asPkcs8().notEncrypted());

		Stream<Arguments> openSslClassic = Arrays.stream(OpenSslClassicAlgorithm.values())
				.map(alg -> Arguments.of(true, false, (Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b
						.asOpenSslClassic().encrypted(PASSWORD, alg)));

		Arguments openSslClassicAes128 = Arguments.of(true, false,
				(Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b.asOpenSslClassic()
						.encryptedAes128(PASSWORD));
		Arguments openSslClassicAes256 = Arguments.of(true, false,
				(Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b.asOpenSslClassic()
						.encryptedAes256(PASSWORD));
		Arguments openSslClassicTrippleDes = Arguments.of(true, false,
				(Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b.asOpenSslClassic()
						.encryptedTrippleDes(PASSWORD));

		Arguments openSslClassicNotEncrypted = Arguments.of(false, false,
				(Function<PrivateKeyPemWriterBuilder, PrivateKeyPemWriter>) b -> b.asOpenSslClassic().notEncrypted());

		return Stream.of(pkcs8, openSslClassic,
				Stream.of(pkcs8NotEncrypted, pkcs8Aes128, pkcs8Aes256, pkcs8TrippleDes, openSslClassicNotEncrypted,
						openSslClassicAes128, openSslClassicAes256, openSslClassicTrippleDes))
				.flatMap(Function.identity());
	}

	@Test
	void writeReadCertificationRequestString() throws Exception
	{
		JcaPKCS10CertificationRequest request = createRequest();

		String pem = PemWriter.writeCertificationRequest(request);
		assertNotNull(pem);
		assertFalse(pem.isBlank());

		JcaPKCS10CertificationRequest readRequest = PemReader.readCertificateRequest(pem);
		assertNotNull(readRequest);
		assertEquals(request, readRequest);
	}

	@Test
	void writeReadCertificationRequestFile(@TempDir Path tmp) throws Exception
	{
		JcaPKCS10CertificationRequest request = createRequest();

		Path csrPath = tmp.resolve("csr.pem");

		PemWriter.writeCertificationRequest(request, csrPath);

		JcaPKCS10CertificationRequest readRequest = PemReader.readCertificateRequest(csrPath);
		assertNotNull(readRequest);
		assertEquals(request, readRequest);
	}

	private JcaPKCS10CertificationRequest createRequest()
	{
		CertificationRequestBuilder builder = ca.createCertificationRequestBuilder();
		X500Name subject = builder.createName("DE", null, null, null, null, "JUnit Test Client");
		KeyPair keyPair = builder.getKeyPairGenerator().generateKeyPair();
		return builder.createCertificationRequest(keyPair, subject);
	}

	@Test
	void writeReadCertificateRevocationListString() throws Exception
	{
		X509CRL crl = ca.createRevocationList(List.of());

		String pem = PemWriter.writeCertificateRevocationList(crl);
		assertNotNull(pem);
		assertFalse(pem.isBlank());

		X509CRL readCrl = PemReader.readCertificateRevocationList(pem);
		assertNotNull(readCrl);
		assertEquals(crl, readCrl);
	}

	@Test
	void writeReadCertificateRevocationListFile(@TempDir Path tmp) throws Exception
	{
		X509CRL crl = ca.createRevocationList(List.of());

		Path crlPath = tmp.resolve("csr.pem");

		PemWriter.writeCertificateRevocationList(crl, crlPath);

		X509CRL readCrl = PemReader.readCertificateRevocationList(crlPath);
		assertNotNull(readCrl);
		assertEquals(crl, readCrl);
	}

	@Test
	void writeReadCertificatesString() throws Exception
	{
		X509Certificate cert = ca.getCertificate();

		String pem = PemWriter.writeCertificates(Arrays.asList(cert, cert, cert), true);
		assertNotNull(pem);
		assertFalse(pem.isBlank());

		List<X509Certificate> readCerts = PemReader.readCertificates(pem);
		assertNotNull(readCerts);
		assertEquals(3, readCerts.size());
		readCerts.stream().forEach(readCert -> assertEquals(cert, readCert));
	}

	@Test
	void writeReadCertificatesFile(@TempDir Path tmp) throws Exception
	{
		X509Certificate cert = ca.getCertificate();

		Path certsPath = tmp.resolve("certs.pem");

		PemWriter.writeCertificates(new X509Certificate[] { cert, cert, cert }, true, certsPath);

		List<X509Certificate> readCerts = PemReader.readCertificates(certsPath);
		assertNotNull(readCerts);
		assertEquals(3, readCerts.size());
		readCerts.stream().forEach(readCert -> assertEquals(cert, readCert));
	}

	@ParameterizedTest
	@MethodSource("readCertKeyArguments")
	void readCertKey(Path file, char[] password) throws Exception
	{
		PrivateKey key = PemReader.readPrivateKey(file, password);
		assertNotNull(key);
	}

	private static Stream<Arguments> readCertKeyArguments()
	{
		final Path folder = Paths.get("src/test/resources");

		Stream<String> notEncrypted = Stream.of("classic_not_encrypted", "pkcs1_not_encrypted");
		Stream<String> encrypted = Stream.of("cert_key", "classic_3des", "classic_aes128", "classic_aes256",
				"pkcs8_3des", "pkcs8_aes128", "pkcs8_aes256");

		return Stream.concat(notEncrypted.map(f -> f + ".pem").map(folder::resolve).map(f -> Arguments.of(f, null)),
				encrypted.map(f -> f + ".pem").map(folder::resolve).map(f -> Arguments.of(f, PASSWORD)));
	}

	@Test
	void readCertKeyNull() throws Exception
	{
		assertThrows(NullPointerException.class, () -> PemReader.readPrivateKey((String) null));
		assertThrows(NullPointerException.class, () -> PemReader.readPrivateKey((String) null, null));
		assertThrows(NullPointerException.class, () -> PemReader.readPrivateKey((InputStream) null));
		assertThrows(NullPointerException.class, () -> PemReader.readPrivateKey((InputStream) null, null));
		assertThrows(NullPointerException.class, () -> PemReader.readPrivateKey((Path) null));
		assertThrows(NullPointerException.class, () -> PemReader.readPrivateKey((Path) null, null));
	}

	@Test
	void readCertKeyNoPassword() throws Exception
	{
		assertThrows(NullPointerException.class,
				() -> PemReader.readPrivateKey(Paths.get("src/test/resources/cert_key.pem")));
		assertThrows(NullPointerException.class,
				() -> PemReader.readPrivateKey(Paths.get("src/test/resources/cert_key.pem"), null));

		assertThrows(IOException.class,
				() -> PemReader.readPrivateKey(Paths.get("src/test/resources/cert_key.pem"), new char[0]));
		assertThrows(IOException.class, () -> PemReader.readPrivateKey(Paths.get("src/test/resources/cert_key.pem"),
				"bad password".toCharArray()));
	}

	@Test
	void readCertReq() throws Exception
	{
		JcaPKCS10CertificationRequest req = PemReader
				.readCertificateRequest(Paths.get("src/test/resources/cert_req.pem"));
		assertNotNull(req);
	}

	@Test
	void readCertReqNull() throws Exception
	{
		assertThrows(NullPointerException.class, () -> PemReader.readCertificateRequest((String) null));
		assertThrows(NullPointerException.class, () -> PemReader.readCertificateRequest((InputStream) null));
		assertThrows(NullPointerException.class, () -> PemReader.readCertificateRequest((Path) null));
	}
}

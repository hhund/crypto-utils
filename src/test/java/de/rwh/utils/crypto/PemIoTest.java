package de.rwh.utils.crypto;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.rwh.utils.crypto.CertificateHelper;
import de.rwh.utils.crypto.CertificateAuthority;
import de.rwh.utils.crypto.io.PemIo;

public class PemIoTest
{
	private Path pemFile;

	@Before
	public void before()
	{
		pemFile = Paths.get("target", UUID.randomUUID().toString() + ".pem");
	}

	@After
	public void after() throws IOException
	{
		Files.deleteIfExists(pemFile);
	}

	@Test
	public void testWriteReadPrivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException
	{
		RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) CertificateHelper.createKeyPair(
				CertificateHelper.DEFAULT_KEY_ALGORITHM, 2048).getPrivate();

		PemIo.writePrivateKeyToPem(privateKey, pemFile);

		RSAPrivateCrtKey readPrivateKey = PemIo.readPrivateKeyFromPem(pemFile);

		assertEquals(privateKey, readPrivateKey);
	}

	@Test
	public void testWriteReadPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
	{
		RSAPublicKey publicKey = (RSAPublicKey) CertificateHelper.createKeyPair(
				CertificateHelper.DEFAULT_KEY_ALGORITHM, 2048).getPublic();

		PemIo.writePublicKeyToPem(publicKey, pemFile);

		RSAPublicKey readPublicKey = PemIo.readPublicKeyFromPem(pemFile);

		assertEquals(publicKey, readPublicKey);
	}

	@Test
	public void testWriteReadCertificate() throws InvalidKeyException, NoSuchAlgorithmException, KeyStoreException,
			CertificateException, OperatorCreationException, IllegalStateException, IOException
	{
		CertificateAuthority.registerBouncyCastleProvider();

		CertificateAuthority ca = new CertificateAuthority("DE", null, null, null, null, "Test-CA");
		ca.initialize();

		X509Certificate certificate = ca.getCertificate();

		PemIo.writeX509CertificateToPem(certificate, pemFile);

		X509Certificate readCertificate = PemIo.readX509CertificateFromPem(pemFile);

		assertEquals(certificate, readCertificate);
	}
}

package de.hsheilbronn.mi.utils.crypto;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.hsheilbronn.mi.utils.crypto.io.CsrIo;

public class CsrIoTest
{
	private Path csrFile;

	@Before
	public void before()
	{
		csrFile = Paths.get("target", UUID.randomUUID().toString() + ".csr");
	}

	@After
	public void after() throws IOException
	{
		Files.deleteIfExists(csrFile);
	}

	@Test
	public void testReadWrite() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException,
			OperatorCreationException, IllegalStateException
	{
		CertificationRequestBuilder.registerBouncyCastleProvider();

		X500Name subject = CertificationRequestBuilder.createSubject("DE", null, null, null, null, "Test");

		KeyPair rsaKeyPair = CertificateHelper.createKeyPair(CertificateHelper.DEFAULT_KEY_ALGORITHM, 2048);
		JcaPKCS10CertificationRequest serverRequest = CertificationRequestBuilder.createServerCertificationRequest(
				subject, rsaKeyPair);

		CsrIo.writeJcaPKCS10CertificationRequestToCsr(serverRequest, csrFile);

		JcaPKCS10CertificationRequest readRequest = CsrIo.readJcaPKCS10CertificationRequestFromCsr(csrFile);

		assertEquals(serverRequest, readRequest);
	}
}

package de.hsheilbronn.mi.utils.crypto.io;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

public final class CsrIo extends AbstractCertIo
{
	public static final String CSR_FILE_EXTENSION = ".csr";

	private static final Charset CHAR_SET = StandardCharsets.UTF_8;
	private static final int LINE_LENGTH = 64;

	private static final String REQUEST_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----";
	private static final String REQUEST_END = "-----END CERTIFICATE REQUEST-----";

	private CsrIo()
	{
	}

	public static void writeJcaPKCS10CertificationRequestToCsr(JcaPKCS10CertificationRequest request, Path csrFile)
			throws IOException
	{
		byte[] encodedRequest = request.getEncoded();

		writeEncoded(encodedRequest, csrFile, REQUEST_BEGIN, REQUEST_END, CHAR_SET, LINE_LENGTH);
	}

	public static JcaPKCS10CertificationRequest readJcaPKCS10CertificationRequestFromCsr(Path csrFile)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		byte[] encodedCertificationRequest = readEncoded(csrFile, REQUEST_BEGIN, REQUEST_END, CHAR_SET, LINE_LENGTH);

		return new JcaPKCS10CertificationRequest(encodedCertificationRequest);
	}
}

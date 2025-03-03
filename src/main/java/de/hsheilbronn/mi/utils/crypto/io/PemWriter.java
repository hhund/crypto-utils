package de.hsheilbronn.mi.utils.crypto.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

import de.hsheilbronn.mi.utils.crypto.ca.CertificationRequest;

public final class PemWriter
{
	private PemWriter()
	{
	}

	private static final int LINE_LENGTH = 64;

	private static final String REQUEST_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----";
	private static final String REQUEST_END = "-----END CERTIFICATE REQUEST-----";

	private static final String PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
	private static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

	private static final String CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----";
	private static final String CERTIFICATE_END = "-----END CERTIFICATE-----";

	private static final String CRL_BEGIN = "-----BEGIN X509 CRL-----";
	private static final String CRL_END = "-----END X509 CRL-----";

	@FunctionalInterface
	private interface ConsumerWithIOException<T>
	{
		void accept(T t) throws IOException;
	}

	private static String toString(ConsumerWithIOException<OutputStream> writer)
	{
		try (ByteArrayOutputStream out = new ByteArrayOutputStream())
		{
			writer.accept(out);

			return new String(out.toByteArray(), StandardCharsets.UTF_8);
		}
		catch (IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	private static void toFile(ConsumerWithIOException<OutputStream> writer, Path file) throws IOException
	{
		try (OutputStream out = Files.newOutputStream(file))
		{
			writer.accept(out);
		}
	}

	private static void writeEncoded(String firstLine, String heading, byte[] data, String lastLine, int lineLength,
			OutputStream out) throws IOException
	{
		byte[] base64Encoded = Base64.getEncoder().encode(data);

		if (heading != null)
		{
			out.write(heading.getBytes(StandardCharsets.UTF_8));
			out.write('\n');
		}

		out.write(firstLine.getBytes(StandardCharsets.UTF_8));
		out.write('\n');

		for (int s = 0; s < base64Encoded.length; s += lineLength)
		{
			out.write(base64Encoded, s, Math.min(lineLength, base64Encoded.length - s));
			out.write('\n');
		}

		out.write(lastLine.getBytes(StandardCharsets.UTF_8));
		out.write('\n');
	}

	public static String writeCertificationRequest(CertificationRequest request)
	{
		return toString(out -> writeCertificationRequest(request, out));
	}

	public static void writeCertificationRequest(CertificationRequest request, Path pem) throws IOException
	{
		toFile(out -> writeCertificationRequest(request, out), pem);
	}

	public static void writeCertificationRequest(CertificationRequest request, OutputStream out) throws IOException
	{
		byte[] encodedRequest = request.getRequest().getEncoded();

		writeEncoded(REQUEST_BEGIN, null, encodedRequest, REQUEST_END, LINE_LENGTH, out);
	}

	public static String writeCertificateRevocationList(X509CRL crl)
	{
		return toString(out -> writeCertificateRevocationList(crl, out));
	}

	public static void writeCertificateRevocationList(X509CRL crl, Path pem) throws IOException
	{
		toFile(out -> writeCertificateRevocationList(crl, out), pem);
	}

	public static void writeCertificateRevocationList(X509CRL crl, OutputStream out) throws IOException
	{
		try
		{
			byte[] encodedCrl = crl.getEncoded();

			writeEncoded(CRL_BEGIN, null, encodedCrl, CRL_END, LINE_LENGTH, out);
		}
		catch (CRLException e)
		{
			throw new IOException(e);
		}
	}

	private static String toSubjectString(X509Certificate certificate)
	{
		return "subject: " + certificate.getSubjectX500Principal().getName(X500Principal.RFC1779);
	}

	public static String writeCertificate(X509Certificate certificate)
	{
		return writeCertificate(certificate, false);
	}

	public static String writeCertificate(X509Certificate certificate, boolean includeSubjectHeader)
	{
		return toString(out -> writeCertificate(certificate, includeSubjectHeader, out));
	}

	public static void writeCertificate(X509Certificate certificate, Path pem) throws IOException
	{
		writeCertificate(certificate, false, pem);
	}

	public static void writeCertificate(X509Certificate certificate, boolean includeSubjectHeader, Path pem)
			throws IOException
	{
		toFile(out -> writeCertificate(certificate, includeSubjectHeader, out), pem);
	}

	public static void writeCertificate(X509Certificate certificate, OutputStream out) throws IOException
	{
		writeCertificate(certificate, false, out);
	}

	public static void writeCertificate(X509Certificate certificate, boolean includeSubjectHeader, OutputStream out)
			throws IOException
	{
		try
		{
			String subjectString = includeSubjectHeader ? toSubjectString(certificate) : null;
			byte[] encodedCertificate = certificate.getEncoded();

			writeEncoded(CERTIFICATE_BEGIN, subjectString, encodedCertificate, CERTIFICATE_END, LINE_LENGTH, out);
		}
		catch (CertificateEncodingException e)
		{
			throw new IOException(e);
		}
	}

	public static String writeCertificates(X509Certificate[] certificates)
	{
		return writeCertificates(certificates, false);
	}

	public static String writeCertificates(X509Certificate[] certificates, boolean includeSubjectHeaders)
	{
		return toString(out -> writeCertificates(certificates, includeSubjectHeaders, out));
	}

	public static void writeCertificates(X509Certificate[] certificates, Path pem) throws IOException
	{
		writeCertificates(certificates, false, pem);
	}

	public static void writeCertificates(X509Certificate[] certificates, boolean includeSubjectHeaders, Path pem)
			throws IOException
	{
		toFile(out -> writeCertificates(certificates, includeSubjectHeaders, out), pem);
	}

	public static void writeCertificates(X509Certificate[] certificates, OutputStream out) throws IOException
	{
		writeCertificates(certificates, false, out);
	}

	public static void writeCertificates(X509Certificate[] certificates, boolean includeSubjectHeaders,
			OutputStream out) throws IOException
	{
		writeCertificates(List.of(certificates), includeSubjectHeaders, out);
	}

	public static String writeCertificates(Collection<? extends X509Certificate> certificates)
	{
		return writeCertificates(certificates, false);
	}

	public static String writeCertificates(Collection<? extends X509Certificate> certificates,
			boolean includeSubjectHeaders)
	{
		return toString(out -> writeCertificates(certificates, includeSubjectHeaders, out));
	}

	public static void writeCertificates(Collection<? extends X509Certificate> certificates, Path pem)
			throws IOException
	{
		writeCertificates(certificates, false, pem);
	}

	public static void writeCertificates(Collection<? extends X509Certificate> certificates,
			boolean includeSubjectHeaders, Path pem) throws IOException
	{
		toFile(out -> writeCertificates(certificates, includeSubjectHeaders, out), pem);
	}

	public static void writeCertificates(Collection<? extends X509Certificate> certificates, OutputStream out)
			throws IOException
	{
		writeCertificates(certificates, false, out);
	}

	public static void writeCertificates(Collection<? extends X509Certificate> certificates,
			boolean includeSubjectHeaders, OutputStream out) throws IOException
	{
		try
		{
			for (X509Certificate certificate : certificates)
			{
				String subjectString = includeSubjectHeaders ? toSubjectString(certificate) : null;
				byte[] encodedCertificate = certificate.getEncoded();

				writeEncoded(CERTIFICATE_BEGIN, subjectString, encodedCertificate, CERTIFICATE_END, LINE_LENGTH, out);
			}
		}
		catch (CertificateEncodingException e)
		{
			throw new IOException(e);
		}
	}

	public static String writePublicKey(RSAPublicKey publicKey)
	{
		return toString(out -> writePublicKey(publicKey, out));
	}

	public static void writePublicKey(RSAPublicKey publicKey, Path pem) throws IOException
	{
		toFile(out -> writePublicKey(publicKey, out), pem);
	}

	public static void writePublicKey(RSAPublicKey publicKey, OutputStream out) throws IOException
	{
		byte[] encodedPublicKey = publicKey.getEncoded();

		writeEncoded(PUBLIC_KEY_BEGIN, null, encodedPublicKey, PUBLIC_KEY_END, LINE_LENGTH, out);
	}

	public static abstract class PrivateKeyPemWriter
	{
		private final PrivateKey privateKey;

		protected PrivateKeyPemWriter(PrivateKey privateKey)
		{
			Objects.requireNonNull(privateKey, "privateKey");

			this.privateKey = privateKey;
		}

		@Override
		public String toString()
		{
			return PemWriter.toString(this::toStream);
		}

		public void toFile(Path pem) throws IOException
		{
			PemWriter.toFile(this::toStream, pem);
		}

		public void toStream(OutputStream out) throws IOException
		{
			toStream(out, privateKey);
		}

		protected abstract void toStream(OutputStream out, PrivateKey privateKey) throws IOException;
	}

	public static final class PrivateKeyPemWriterOpenSslClassicBuilder
	{
		private final PrivateKey privateKey;

		public PrivateKeyPemWriterOpenSslClassicBuilder(PrivateKey privateKey)
		{
			this.privateKey = privateKey;
		}

		private static final class PrivateKeyPemWriterOpenSslClassic extends PrivateKeyPemWriter
		{
			private final PEMEncryptor encryptor;

			public PrivateKeyPemWriterOpenSslClassic(PrivateKey privateKey, PEMEncryptor encryptor)
			{
				super(privateKey);

				this.encryptor = encryptor;
			}

			@Override
			public void toStream(OutputStream out, PrivateKey privateKey) throws IOException
			{
				try (OutputStreamWriter writer = new OutputStreamWriter(out);
						org.bouncycastle.util.io.pem.PemWriter pemWriter = new org.bouncycastle.util.io.pem.PemWriter(
								writer))
				{
					PrivateKeyInfo info = PrivateKeyInfo.getInstance(privateKey.getEncoded());
					pemWriter.writeObject(new MiscPEMGenerator(info, encryptor));
				}
			}
		}

		public static enum OpenSslClassicAlgorithm
		{
			TRIPPLE_DES("DES-EDE3-CBC"), AES_128("AES-128-CBC"), AES_256("AES-256-CBC");

			private final String value;

			private OpenSslClassicAlgorithm(String value)
			{
				this.value = value;
			}

			public String getValue()
			{
				return value;
			}
		}

		public PrivateKeyPemWriter encryptedTrippleDes(char[] password)
		{
			return encrypted(password, OpenSslClassicAlgorithm.TRIPPLE_DES);
		}

		public PrivateKeyPemWriter encryptedAes128(char[] password)
		{
			return encrypted(password, OpenSslClassicAlgorithm.AES_128);
		}

		public PrivateKeyPemWriter encryptedAes256(char[] password)
		{
			return encrypted(password, OpenSslClassicAlgorithm.AES_256);
		}

		public PrivateKeyPemWriter encrypted(char[] password, OpenSslClassicAlgorithm algorithm)
		{
			Objects.requireNonNull(password, "password");

			PEMEncryptor encryptor = new JcePEMEncryptorBuilder(algorithm.getValue())
					.setProvider(new BouncyCastleProvider()).build(password);

			return encrypted(encryptor);
		}

		public PrivateKeyPemWriter encrypted(PEMEncryptor encryptor)
		{
			Objects.requireNonNull(encryptor, "encryptor");

			return new PrivateKeyPemWriterOpenSslClassic(privateKey, encryptor);
		}

		public PrivateKeyPemWriter notEncrypted()
		{
			return new PrivateKeyPemWriterOpenSslClassic(privateKey, null);
		}
	}

	public static final class PrivateKeyPemWriterPkcs8Builder
	{
		private final PrivateKey privateKey;

		public PrivateKeyPemWriterPkcs8Builder(PrivateKey privateKey)
		{
			this.privateKey = privateKey;
		}

		public static final class PrivateKeyPemWriterPkcs8 extends PrivateKeyPemWriter
		{
			private final OutputEncryptor encryptor;

			public PrivateKeyPemWriterPkcs8(PrivateKey privateKey, OutputEncryptor encryptor)
			{
				super(privateKey);

				this.encryptor = encryptor;
			}

			@Override
			public void toStream(OutputStream out, PrivateKey privateKey) throws IOException
			{
				try (OutputStreamWriter writer = new OutputStreamWriter(out);
						org.bouncycastle.util.io.pem.PemWriter pemWriter = new org.bouncycastle.util.io.pem.PemWriter(
								writer))
				{
					PrivateKeyInfo info = PrivateKeyInfo.getInstance(privateKey.getEncoded());
					pemWriter.writeObject(new PKCS8Generator(info, encryptor));
				}
			}
		}

		public static enum Pkcs8Algorithm
		{
			TRIPPLE_DES(PKCSObjectIdentifiers.des_EDE3_CBC), AES_128(NISTObjectIdentifiers.id_aes128_CBC), AES_256(
					NISTObjectIdentifiers.id_aes256_CBC);

			private final ASN1ObjectIdentifier value;

			private Pkcs8Algorithm(ASN1ObjectIdentifier value)
			{
				this.value = value;
			}

			public ASN1ObjectIdentifier getValue()
			{
				return value;
			}
		}

		public PrivateKeyPemWriter encryptedTrippleDes(char[] password)
		{
			return encrypted(password, Pkcs8Algorithm.TRIPPLE_DES);
		}

		public PrivateKeyPemWriter encryptedAes128(char[] password)
		{
			return encrypted(password, Pkcs8Algorithm.AES_128);
		}

		public PrivateKeyPemWriter encryptedAes256(char[] password)
		{
			return encrypted(password, Pkcs8Algorithm.AES_256);
		}

		public PrivateKeyPemWriter encrypted(char[] password, Pkcs8Algorithm algorithm)
		{
			Objects.requireNonNull(password, "password");

			try
			{
				OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(
						new PBKDF2Config.Builder().withPRF(PBKDF2Config.PRF_SHA256).withIterationCount(2048).build(),
						algorithm.getValue()).setProvider(new BouncyCastleProvider()).build(password);

				return encrypted(encryptor);
			}
			catch (OperatorCreationException e)
			{
				throw new RuntimeException(e);
			}
		}

		public PrivateKeyPemWriter encrypted(OutputEncryptor encryptor)
		{
			Objects.requireNonNull(encryptor, "encryptor");

			return new PrivateKeyPemWriterPkcs8(privateKey, encryptor);
		}

		public PrivateKeyPemWriter notEncrypted()
		{
			return new PrivateKeyPemWriterPkcs8(privateKey, null);
		}
	}

	public static class PrivateKeyPemWriterBuilder
	{
		private final PrivateKey key;

		public PrivateKeyPemWriterBuilder(PrivateKey key)
		{
			this.key = Objects.requireNonNull(key, "key");
		}

		public PrivateKeyPemWriterOpenSslClassicBuilder asOpenSslClassic()
		{
			return new PrivateKeyPemWriterOpenSslClassicBuilder(key);
		}

		public PrivateKeyPemWriterPkcs8Builder asPkcs8()
		{
			return new PrivateKeyPemWriterPkcs8Builder(key);
		}
	}

	public static PrivateKeyPemWriterBuilder writePrivateKey(PrivateKey key)
	{
		return new PrivateKeyPemWriterBuilder(key);
	}
}

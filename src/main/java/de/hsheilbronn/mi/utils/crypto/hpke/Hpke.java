package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import de.hsheilbronn.mi.utils.crypto.hpke.KeySchedule.Result;

/**
 * RFC 9180 Hybrid Public Key Encryption implementation with support for modes 0 and 1. The encryption produces a
 * [header][encapsulation][chunk0]...[chunkN] wire-format.<br>
 * <br>
 * Chunks 1 to n-1 have a fixed length. The final chunk may be shorter. Supported chunk lengths are defined in
 * {@link ChunkLength}.<br>
 * <br>
 * The header format is defined in {@link Header}. Lengths of the encapsulation are define by the RFC, see
 * {@link KemId}. <br>
 * The AAD tag is defined as: [header][sequence, 12 bytes][final-chunk-flag, 1 byte].
 */
public class Hpke
{
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private final PskProvider pskProvider;
	private final SecureRandom secureRandom;

	public Hpke(PskProvider pskProvider)
	{
		this(pskProvider, SECURE_RANDOM);
	}

	public Hpke(PskProvider pskProvider, SecureRandom secureRandom)
	{
		this.pskProvider = Objects.requireNonNull(pskProvider, "pskProvider");
		this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
	}

	protected KeySchedule createKeySchedule(Header header)
	{
		return new KeySchedule(header.getMode(), header.getKemId(), header.getKdfId(), header.getAeadId(),
				header.getCanonical());
	}

	public InputStream encrypt(Header header, InputStream plainText, PublicKey publicKey)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, GeneralSecurityException
	{
		Objects.requireNonNull(header, "header");
		Objects.requireNonNull(plainText, "plainText");
		Objects.requireNonNull(publicKey, "publicKey");

		Encapsulated encapsulated = header.getKemId().toKem().getEncapsulated(publicKey, secureRandom);

		Result keyScheduleResult = createKeySchedule(header).executeKeySchedule(encapsulated.key());

		Cipher cipher = header.getAeadId().toCipher();

		ChunkedInputStreamEnumeration chunks = new ChunkedInputStreamEnumeration(header.getChunkLength(),
				keyScheduleResult.baseNonce(), plainText,
				(byte[] iv, byte[] sequence, boolean finished, byte[] currentChunk) ->
				{
					header.getAeadId().initEncryptionCipher(cipher, keyScheduleResult.key(), iv);

					cipher.updateAAD(createAAD(header, sequence, finished));
					byte[] encrypted = cipher.doFinal(currentChunk);

					return new ByteArrayInputStream(encrypted);
				});

		try
		{
			return new SequenceInputStream(
					Collections.enumeration(List.of(new ByteArrayInputStream(header.getCanonical()),
							new ByteArrayInputStream(encapsulated.encapsulation()),
							new SequenceInputStreamForRuntimeIOException(chunks))));
		}
		catch (RuntimeIOException e)
		{
			throw (IOException) e.getCause();
		}
	}

	public void encrypt(Header header, InputStream plainText, PublicKey publicKey, OutputStream out)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, GeneralSecurityException
	{
		Objects.requireNonNull(out, "out");

		encrypt(header, plainText, publicKey).transferTo(out);
	}

	public final InputStream decrypt(InputStream encrypted, PrivateKey privateKey)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, DecapsulateException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, GeneralSecurityException, KeyNotFoundException
	{
		return decrypt(encrypted, _ -> privateKey);
	}

	public final InputStream decrypt(InputStream encrypted, ReceiverKeyProvider receiverKeyProvider)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, DecapsulateException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, GeneralSecurityException, KeyNotFoundException
	{
		Objects.requireNonNull(encrypted, "encrypted");
		Objects.requireNonNull(receiverKeyProvider, "receiverKeyProvider");

		Header header = Header.from(encrypted, pskProvider);

		PrivateKey privateKey = receiverKeyProvider.retrieve(header.getReceiverKeyId());

		byte[] encapsulation = new byte[header.getKemId().getEncapsulationLength()];
		ByteEncoding.expectRead(header.getKemId().getEncapsulationLength(), encrypted.read(encapsulation));

		SecretKey sharedSecret = header.getKemId().toKem().getSharedSecret(privateKey, encapsulation);

		Result keyScheduleResult = createKeySchedule(header).executeKeySchedule(sharedSecret);

		Cipher cipher = header.getAeadId().toCipher();

		ChunkedInputStreamEnumeration chunks = new ChunkedInputStreamEnumeration(
				header.getChunkLength() + (header.getAeadId().getAuthenticationTagLengthBits() / 8),
				keyScheduleResult.baseNonce(), encrypted,
				(byte[] iv, byte[] sequence, boolean finished, byte[] currentChunk) ->
				{
					header.getAeadId().initDecryptionCipher(cipher, keyScheduleResult.key(), iv);

					cipher.updateAAD(createAAD(header, sequence, finished));
					byte[] decrypted = cipher.doFinal(currentChunk);

					return new ByteArrayInputStream(decrypted);
				});

		try
		{
			return new SequenceInputStreamForRuntimeIOException(chunks);
		}
		catch (RuntimeIOException e)
		{
			throw (IOException) e.getCause();
		}
	}

	private byte[] createAAD(Header header, byte[] sequence, boolean finished)
	{
		return ByteEncoding.concat(header.getCanonical(), sequence, ByteEncoding.i2osp1(finished ? 1 : 0));
	}

	public final void decrypt(InputStream encrypted, PrivateKey privateKey, OutputStream plainText)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, DecapsulateException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, GeneralSecurityException, KeyNotFoundException
	{
		decrypt(encrypted, _ -> privateKey, plainText);
	}

	public final void decrypt(InputStream encrypted, ReceiverKeyProvider receiverKeyProvider, OutputStream plainText)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, DecapsulateException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, GeneralSecurityException, KeyNotFoundException
	{
		Objects.requireNonNull(plainText, "plainText");

		decrypt(encrypted, receiverKeyProvider).transferTo(plainText);
	}
}

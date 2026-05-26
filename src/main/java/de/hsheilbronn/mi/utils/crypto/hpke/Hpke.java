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
 * <a href="https://www.rfc-editor.org/info/rfc9180">RFC 9180 Hybrid Public Key Encryption</a> implementation with
 * support for modes 0 and 1. The encryption produces a wire-format not defined in RFC 9180 for use in the encryption of
 * large files.<br>
 * <br>
 * The general wire-format is defined as: <code>[header][encapsulation][chunk0]...[chunkN]</code><br>
 * <br>
 * The header format is specified in classes implementing {@link Protocol}. Lengths of the encapsulation are define by
 * the RFC, see {@link KemId}.<br>
 * <br>
 * Chunks 1 to n-1 have a fixed length. The final chunk may be shorter. The chunk length is defined via
 * {@link Protocol#getChunkLength()}.<br>
 * <br>
 * The RFC 9180 key-schedule is implemented by {@link KeySchedule}, with additional "info" supplied to the schedule by
 * {@link Protocol#getKdfInfo()}.<br>
 * <br>
 * Additional authenticated data per chunk is defined by the sequence number and a one byte boolean flag for the final
 * chunk, see {@link #createAad(byte[], boolean)}.
 */
public class Hpke
{
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private final ProtocolFactory protocolFactory;
	private final SecureRandom secureRandom;

	/**
	 * Uses {@link #SECURE_RANDOM}.
	 * 
	 * @param protocolFactory
	 *            not <code>null</code>
	 */
	public Hpke(ProtocolFactory protocolFactory)
	{
		this(protocolFactory, SECURE_RANDOM);
	}

	/**
	 * @param protocolFactory
	 *            not <code>null</code>
	 * @param secureRandom
	 *            not <code>null</code>
	 */
	public Hpke(ProtocolFactory protocolFactory, SecureRandom secureRandom)
	{
		this.protocolFactory = Objects.requireNonNull(protocolFactory, "protocolFactory");
		this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
	}

	protected KeySchedule createKeySchedule(Protocol protocol)
	{
		return new KeySchedule(protocol.getMode(), protocol.getKemId(), protocol.getKdfId(), protocol.getAeadId(),
				protocol.getKdfInfo(), protocolFactory.getPreSharedKeyProvider());
	}

	protected byte[] createAad(byte[] sequence, boolean finished)
	{
		return ByteEncoding.concat(sequence, ByteEncoding.i2osp1(finished ? 1 : 0));
	}

	/**
	 * Encrypts the given plain-text into chunks using the wire-format configure with the given <b>header</b>.<br>
	 * <br>
	 * For an empty <b>plainText</b> stream a single encrypted chunk will be emitted.
	 * 
	 * @param protocol
	 *            not <code>null</code>
	 * @param plainText
	 *            not <code>null</code>
	 * @param publicKey
	 *            not <code>null</code>
	 * @return crypt-text
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws GeneralSecurityException
	 * @throws KeyNotFoundException
	 * @throws KeyNotSupportedException
	 */
	public InputStream encrypt(Protocol protocol, InputStream plainText, PublicKey publicKey)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, GeneralSecurityException, KeyNotFoundException, KeyNotSupportedException
	{
		Objects.requireNonNull(protocol, "protocol");
		Objects.requireNonNull(plainText, "plainText");
		Objects.requireNonNull(publicKey, "publicKey");

		Encapsulated encapsulated = protocol.getKemId().toKem().getEncapsulated(publicKey, secureRandom);

		Result keyScheduleResult = createKeySchedule(protocol).executeKeySchedule(encapsulated.key());

		Cipher cipher = protocol.getAeadId().toCipher();

		ChunkedInputStreamEnumeration chunks = new ChunkedInputStreamEnumeration(protocol.getChunkLength().getLength(),
				keyScheduleResult.baseNonce(), plainText,
				(byte[] iv, byte[] sequence, boolean finished, byte[] chunk) ->
				{
					protocol.getAeadId().initEncryptionCipher(cipher, keyScheduleResult.key(), iv);

					cipher.updateAAD(createAad(sequence, finished));

					byte[] encrypted = cipher.doFinal(chunk);

					return new ByteArrayInputStream(encrypted);
				});

		return new SequenceInputStream(Collections.enumeration(
				List.of(protocolFactory.write(protocol), new ByteArrayInputStream(encapsulated.encapsulation()),
						SequenceInputStreamForRuntimeIOException.of(chunks))));
	}

	/**
	 * Encrypts the given plain-text into chunks using the wire-format configure with the given <b>header</b>.<br>
	 * <br>
	 * For an empty <b>plainText</b> stream a single encrypted chunk will be emitted.
	 * 
	 * @param protocol
	 *            not <code>null</code>
	 * @param plainText
	 *            not <code>null</code>
	 * @param publicKey
	 *            not <code>null</code>
	 * @param out
	 *            not <code>null</code>
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws GeneralSecurityException
	 * @throws KeyNotFoundException
	 * @throws KeyNotSupportedException
	 */
	public void encrypt(Protocol protocol, InputStream plainText, PublicKey publicKey, OutputStream out)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, GeneralSecurityException, KeyNotFoundException, KeyNotSupportedException
	{
		Objects.requireNonNull(out, "out");

		encrypt(protocol, plainText, publicKey).transferTo(out);
	}

	/**
	 * Decrypted chunks are emitted as soon as they are successfully decrypted while a later chunk may fail decryption.
	 * 
	 * @param encrypted
	 *            not <code>null</code>
	 * @return plain text
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws DecapsulateException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws GeneralSecurityException
	 * @throws KeyNotFoundException
	 * @throws KeyNotSupportedException
	 */
	public final InputStream decrypt(InputStream encrypted) throws IOException, NoSuchAlgorithmException,
			InvalidKeyException, DecapsulateException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			GeneralSecurityException, KeyNotFoundException, KeyNotSupportedException
	{
		Objects.requireNonNull(encrypted, "encrypted");

		Protocol protocol = protocolFactory.read(encrypted);

		PrivateKey privateKey = protocolFactory.getReceiverPrivateKeyProvider().retrieve(protocol.getReceiverKeyId());

		byte[] encapsulation = encrypted.readNBytes(protocol.getKemId().getEncapsulationLength());
		ByteEncoding.expectRead(protocol.getKemId().getEncapsulationLength(), encapsulation.length);

		SecretKey sharedSecret = protocol.getKemId().toKem().getSharedSecret(privateKey, encapsulation);

		Result keyScheduleResult = createKeySchedule(protocol).executeKeySchedule(sharedSecret);

		Cipher cipher = protocol.getAeadId().toCipher();

		ChunkedInputStreamEnumeration chunks = new ChunkedInputStreamEnumeration(
				protocol.getChunkLength().getLength() + (protocol.getAeadId().getAuthenticationTagLengthBits() / 8),
				keyScheduleResult.baseNonce(), encrypted,
				(byte[] iv, byte[] sequence, boolean finished, byte[] chunk) ->
				{
					protocol.getAeadId().initDecryptionCipher(cipher, keyScheduleResult.key(), iv);

					cipher.updateAAD(createAad(sequence, finished));

					byte[] decrypted = cipher.doFinal(chunk);

					return new ByteArrayInputStream(decrypted);
				});

		return SequenceInputStreamForRuntimeIOException.of(chunks);
	}

	/**
	 * Decrypted chunks are emitted as soon as they are successfully decrypted while a later chunk may fail decryption.
	 * 
	 * @param encrypted
	 *            not <code>null</code>
	 * @param plainText
	 *            not <code>null</code>
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws DecapsulateException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws GeneralSecurityException
	 * @throws KeyNotFoundException
	 * @throws KeyNotSupportedException
	 */
	public final void decrypt(InputStream encrypted, OutputStream plainText) throws IOException,
			NoSuchAlgorithmException, InvalidKeyException, DecapsulateException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, GeneralSecurityException, KeyNotFoundException, KeyNotSupportedException
	{
		decrypt(encrypted).transferTo(plainText);
	}
}

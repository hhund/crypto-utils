package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * The wire-format header is defined with fixed length and fixed order:<br>
 * ["HPKEF", 5 bytes] (magic marker)<br>
 * [version, 1 byte] - see {@link Version}<br>
 * [mode (base, psk), 1 byte] - see {@link Mode}<br>
 * [kem-id, 2 bytes] - see {@link KemId}<br>
 * [kdf-id, 2 byte] - see {@link KdfId}<br>
 * [aead-id, 2 byte] - see {@link AeadId}<br>
 * [chunkLengthExponent, 1 byte] - see {@link ChunkLength}<br>
 * [receiver-key-id, 32 bytes]<br>
 * [pre-shared-key-id, 32 bytes] - (Only if mode = psk)<br>
 */
public class Header
{
	public static final byte[] MAGIC = new byte[] { 'H', 'P', 'K', 'E', 'F' };

	public static final int RECEIVER_KEY_ID_LENGTH = 32;
	public static final int HEADER_LENGHT = RECEIVER_KEY_ID_LENGTH + 14;
	public static final int PSK_ID_LENGTH = 32;

	private final Version version;
	private final Mode mode;
	private final KemId kemId;
	private final KdfId kdfId;
	private final AeadId aeadId;

	private final ChunkLength chunkLength;
	private final byte[] receiverKeyId;

	private byte[] canonical;

	/**
	 * @param version
	 *            not <code>null</code>
	 * @param mode
	 *            not <code>null</code>, if mode {@link Mode#PSK_VALUE}: mode.pskId.length = {@value #PSK_ID_LENGTH}
	 * @param kemId
	 *            not <code>null</code>
	 * @param kdfId
	 *            not <code>null</code>
	 * @param aeadId
	 *            not <code>null</code>
	 * @param chunkLength
	 *            not <code>null</code>
	 * @param receiverKeyId
	 *            not <code>null</code>, length {@value #RECEIVER_KEY_ID_LENGTH}
	 */
	public Header(Version version, Mode mode, KemId kemId, KdfId kdfId, AeadId aeadId, ChunkLength chunkLength,
			byte[] receiverKeyId)
	{
		Objects.requireNonNull(version, "version");

		Objects.requireNonNull(mode, "mode");
		if (mode.isPsk() && mode.getPskId().length != Header.PSK_ID_LENGTH)
			throw new IllegalArgumentException("mode.pskId.length != " + Header.PSK_ID_LENGTH);

		Objects.requireNonNull(kemId, "kemId");
		Objects.requireNonNull(kdfId, "kdfId");
		Objects.requireNonNull(aeadId, "aeadId");
		Objects.requireNonNull(chunkLength, "chunkLength");
		Objects.requireNonNull(receiverKeyId, "receiverKeyId");

		if (receiverKeyId.length != RECEIVER_KEY_ID_LENGTH)
			throw new IllegalArgumentException("receiverKeyId.length != " + RECEIVER_KEY_ID_LENGTH);

		this.version = version;
		this.mode = mode;
		this.kemId = kemId;
		this.kdfId = kdfId;
		this.aeadId = aeadId;
		this.chunkLength = chunkLength;
		this.receiverKeyId = receiverKeyId;
	}

	public byte[] getCanonical()
	{
		if (canonical == null)
			canonical = toCanonical();

		return canonical;
	}

	private byte[] toCanonical()
	{
		ByteBuffer buffer = ByteBuffer.allocate(HEADER_LENGHT + (mode.isPsk() ? PSK_ID_LENGTH : 0));
		buffer.put(MAGIC);
		buffer.put(version.getValueAsI2osp1Byte());
		buffer.put(mode.getValueAsI2osp1Byte());
		buffer.put(kemId.getIdAsI2osp2Bytes());
		buffer.put(kdfId.getIdAsI2osp2Bytes());
		buffer.put(aeadId.getIdAsI2osp2Bytes());
		buffer.put(chunkLength.getExponentAsI2osp1Byte());
		buffer.put(receiverKeyId);

		if (mode.isPsk())
			buffer.put(mode.getPskId());

		return buffer.array();
	}

	public Version getVersion()
	{
		return version;
	}

	public Mode getMode()
	{
		return mode;
	}

	public KemId getKemId()
	{
		return kemId;
	}

	public KdfId getKdfId()
	{
		return kdfId;
	}

	public AeadId getAeadId()
	{
		return aeadId;
	}

	public byte[] getReceiverKeyId()
	{
		return receiverKeyId;
	}

	public int getChunkLength()
	{
		return chunkLength.getLength();
	}

	public static Header from(InputStream stream, PreSharedKeyProvider pskProvider) throws KeyNotFoundException, IOException
	{
		Objects.requireNonNull(stream, "stream");
		Objects.requireNonNull(pskProvider, "pskProvider");

		byte[] magicValue = new byte[MAGIC.length];
		ByteEncoding.expectRead(MAGIC.length, stream.read(magicValue));

		if (!Arrays.equals(MAGIC, magicValue))
			throw new IOException("Magic value not supported");

		int versionValue = stream.read();
		ByteEncoding.throwIfTruncated(versionValue);

		if (Version.V1.getValue() != (byte) versionValue)
			throw new IOException("Version not supported");

		int modeValue = stream.read();
		ByteEncoding.throwIfTruncated(modeValue);

		int remainingHeaderLength;
		if (Mode.BASE_VALUE == (byte) modeValue)
			remainingHeaderLength = HEADER_LENGHT - (MAGIC.length + 2);
		else if (Mode.PSK_VALUE == (byte) modeValue)
			remainingHeaderLength = HEADER_LENGHT + PSK_ID_LENGTH - (MAGIC.length + 2);
		else
			throw new IOException("Mode not supported");

		byte[] remainingHeader = new byte[remainingHeaderLength];
		ByteEncoding.expectRead(remainingHeaderLength, stream.read(remainingHeader));

		ByteBuffer buffer = ByteBuffer.wrap(remainingHeader);

		try
		{
			return toHeader(pskProvider, (byte) versionValue, (byte) modeValue, buffer);
		}
		catch (IllegalArgumentException e)
		{
			throw new IOException(e.getMessage());
		}
	}

	public static Header from(byte[] value, PreSharedKeyProvider pskProvider) throws KeyNotFoundException
	{
		Objects.requireNonNull(value, "value");
		if (value.length < HEADER_LENGHT)
			throw new IllegalArgumentException("value.length < " + HEADER_LENGHT);
		Objects.requireNonNull(pskProvider, "pskProvider");

		ByteBuffer buffer = ByteBuffer.wrap(value);

		byte[] magicValue = new byte[MAGIC.length];
		buffer.get(magicValue);

		if (!Arrays.equals(MAGIC, magicValue))
			throw new IllegalArgumentException("Magic value not supported");

		byte versionValue = buffer.get();

		if (Version.V1.getValue() != versionValue)
			throw new IllegalArgumentException("Version not supported");

		byte modeValue = buffer.get();

		if (Mode.BASE_VALUE == modeValue)
		{
			if (value.length != HEADER_LENGHT)
				throw new IllegalArgumentException("Mode 0x00: value.length != " + HEADER_LENGHT);
		}
		else if (Mode.PSK_VALUE == modeValue)
		{
			if (value.length != (HEADER_LENGHT + PSK_ID_LENGTH))
				throw new IllegalArgumentException("Mode 0x01: value.length != " + (HEADER_LENGHT + PSK_ID_LENGTH));
		}
		else
			throw new IllegalArgumentException("Mode not supported");

		return toHeader(pskProvider, versionValue, modeValue, buffer);
	}

	private static Header toHeader(PreSharedKeyProvider pskProvider, byte versionValue, byte modeValue, ByteBuffer buffer)
			throws KeyNotFoundException
	{
		byte[] kemIdValue = new byte[2];
		byte[] kdfIdValue = new byte[2];
		byte[] aeadIdValue = new byte[2];
		byte[] chunkLengthValue = new byte[1];
		byte[] receiverKeyId = new byte[RECEIVER_KEY_ID_LENGTH];

		buffer.get(kemIdValue).get(kdfIdValue).get(aeadIdValue).get(chunkLengthValue).get(receiverKeyId);

		byte[] pskId;
		if (Mode.PSK_VALUE == modeValue)
		{
			pskId = new byte[PSK_ID_LENGTH];
			buffer.get(pskId);
		}
		else
			pskId = null;

		Version version = Version.from(versionValue);
		Mode mode = Mode.from(modeValue, pskId, pskProvider);
		KemId kemId = KemId.from(kemIdValue);
		KdfId kdfId = KdfId.from(kdfIdValue);
		AeadId aeadId = AeadId.from(aeadIdValue);
		ChunkLength chunkLength = ChunkLength.from(chunkLengthValue);

		return new Header(version, mode, kemId, kdfId, aeadId, chunkLength, receiverKeyId);
	}
}

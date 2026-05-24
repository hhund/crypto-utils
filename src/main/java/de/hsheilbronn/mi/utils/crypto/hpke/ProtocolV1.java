package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The wire-format header is defined with fixed length and fixed order:<br>
 * ["HPKEF", 5 bytes] (magic marker)<br>
 * [0x01, 1 byte]<br>
 * [mode (base, psk), 1 byte] - see {@link Mode}<br>
 * [kem-id, 2 bytes] - see {@link KemId}<br>
 * [kdf-id, 2 byte] - see {@link KdfId}<br>
 * [aead-id, 2 byte] - see {@link AeadId}<br>
 * [chunkLengthExponent, 1 byte] - see {@link ChunkLength}<br>
 * [receiver-key-id, 32 bytes]<br>
 * [pre-shared-key-id, 32 bytes] - only if mode = psk<br>
 * <br>
 * Uses "HPKEF" + 0x01 as the KDF info value, see {@link #KDF_INFO}.<br>
 * Supported chunk lengths are defined in {@link ChunkLength}.<br>
 */
public class ProtocolV1 implements Protocol
{
	public static final byte VERSION = (byte) 0x01;
	public static final byte[] KDF_INFO = new byte[] { 'H', 'P', 'K', 'E', 'F', VERSION };

	public static final int RECEIVER_KEY_ID_LENGTH = 32;
	public static final int PRE_SHARED_KEY_ID_LENGTH = 32;

	public static final int HEADER_BASE_LENGTH = 8 + RECEIVER_KEY_ID_LENGTH;
	public static final int HEADER_PSK_LENGTH = HEADER_BASE_LENGTH + PRE_SHARED_KEY_ID_LENGTH;

	private final Mode mode;
	private final KemId kemId;
	private final KdfId kdfId;
	private final AeadId aeadId;

	private final ChunkLength chunkLength;
	private final byte[] receiverKeyId;

	private final AtomicReference<byte[]> canonical = new AtomicReference<>();

	/**
	 * @param mode
	 *            not <code>null</code>, if mode {@link Mode#PSK_VALUE}: mode.pskId.length =
	 *            {@value #PRE_SHARED_KEY_ID_LENGTH}
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
	public ProtocolV1(Mode mode, KemId kemId, KdfId kdfId, AeadId aeadId, ChunkLength chunkLength, byte[] receiverKeyId)
	{
		Objects.requireNonNull(mode, "mode");
		if (mode.isPsk() && mode.getPskId().length != ProtocolV1.PRE_SHARED_KEY_ID_LENGTH)
			throw new IllegalArgumentException("mode.pskId.length not " + ProtocolV1.PRE_SHARED_KEY_ID_LENGTH);

		Objects.requireNonNull(kemId, "kemId");
		Objects.requireNonNull(kdfId, "kdfId");
		Objects.requireNonNull(aeadId, "aeadId");
		Objects.requireNonNull(chunkLength, "chunkLength");
		Objects.requireNonNull(receiverKeyId, "receiverKeyId");

		if (receiverKeyId.length != RECEIVER_KEY_ID_LENGTH)
			throw new IllegalArgumentException("receiverKeyId.length not " + RECEIVER_KEY_ID_LENGTH);

		this.mode = mode;
		this.kemId = kemId;
		this.kdfId = kdfId;
		this.aeadId = aeadId;
		this.chunkLength = chunkLength;
		this.receiverKeyId = receiverKeyId;
	}

	public static ProtocolV1 from(InputStream source) throws IOException
	{
		int modeValue = source.read();
		ByteEncoding.throwIfTruncated(modeValue);

		int remainingHeaderLength;
		if (Mode.BASE_VALUE == (byte) modeValue)
			remainingHeaderLength = HEADER_BASE_LENGTH - 1;
		else if (Mode.PSK_VALUE == (byte) modeValue)
			remainingHeaderLength = HEADER_PSK_LENGTH - 1;
		else
			throw new IOException("Mode not supported");

		byte[] remainingHeader = source.readNBytes(remainingHeaderLength);
		ByteEncoding.expectRead(remainingHeaderLength, remainingHeader.length);

		ByteBuffer buffer = ByteBuffer.wrap(remainingHeader);

		byte[] kemIdValue = new byte[2];
		byte[] kdfIdValue = new byte[2];
		byte[] aeadIdValue = new byte[2];
		byte[] chunkLengthValue = new byte[1];
		byte[] receiverKeyId = new byte[ProtocolV1.RECEIVER_KEY_ID_LENGTH];

		buffer.get(kemIdValue).get(kdfIdValue).get(aeadIdValue).get(chunkLengthValue).get(receiverKeyId);

		byte[] pskId;
		if (Mode.PSK_VALUE == modeValue)
		{
			pskId = new byte[ProtocolV1.PRE_SHARED_KEY_ID_LENGTH];
			buffer.get(pskId);
		}
		else
			pskId = null;

		try
		{
			Mode mode = Mode.from((byte) modeValue, pskId);
			KemId kemId = KemId.from(kemIdValue);
			KdfId kdfId = KdfId.from(kdfIdValue);
			AeadId aeadId = AeadId.from(aeadIdValue);
			ChunkLength chunkLength = ChunkLength.from(chunkLengthValue);

			return new ProtocolV1(mode, kemId, kdfId, aeadId, chunkLength, receiverKeyId);
		}
		catch (IllegalArgumentException e)
		{
			throw new IOException(e.getMessage(), e);
		}
	}

	public byte[] getCanonicalHeader()
	{
		byte[] c = canonical.get();
		if (c == null)
			canonical.compareAndSet(null, toCanonical());

		return canonical.get();
	}

	private byte[] toCanonical()
	{
		ByteBuffer buffer = ByteBuffer.allocate(mode.isPsk() ? HEADER_PSK_LENGTH : HEADER_BASE_LENGTH);
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

	@Override
	public Mode getMode()
	{
		return mode;
	}

	@Override
	public KemId getKemId()
	{
		return kemId;
	}

	@Override
	public KdfId getKdfId()
	{
		return kdfId;
	}

	@Override
	public AeadId getAeadId()
	{
		return aeadId;
	}

	@Override
	public int getChunkLength()
	{
		return chunkLength.getLength();
	}

	@Override
	public byte[] getReceiverKeyId()
	{
		return receiverKeyId.clone();
	}

	@Override
	public byte[] getKdfInfo()
	{
		return KDF_INFO;
	}
}

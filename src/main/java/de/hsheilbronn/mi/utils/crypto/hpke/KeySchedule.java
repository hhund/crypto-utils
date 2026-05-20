package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.HKDFParameterSpec.Expand;
import javax.crypto.spec.HKDFParameterSpec.Extract;

public class KeySchedule
{
	private static final byte[] HPKE = new byte[] { 'H', 'P', 'K', 'E' };
	private static final byte[] HPKE_V1 = new byte[] { 'H', 'P', 'K', 'E', '-', 'v', '1' };
	private static final byte[] PSK_ID_HASH = new byte[] { 'p', 's', 'k', '_', 'i', 'd', '_', 'h', 'a', 's', 'h' };
	private static final byte[] INFO_HASH = new byte[] { 'i', 'n', 'f', 'o', '_', 'h', 'a', 's', 'h' };
	private static final byte[] SECRET = new byte[] { 's', 'e', 'c', 'r', 'e', 't' };
	private static final byte[] KEY = new byte[] { 'k', 'e', 'y' };
	private static final byte[] BASE_NONCE = new byte[] { 'b', 'a', 's', 'e', '_', 'n', 'o', 'n', 'c', 'e' };

	public record Result(SecretKey key, byte[] baseNonce)
	{
	}

	private final Mode mode;
	private final KemId kemId;
	private final KdfId kdfId;
	private final AeadId aeadId;
	private final byte[] info;

	public KeySchedule(Mode mode, KemId kemId, KdfId kdfId, AeadId aeadId)
	{
		this(mode, kemId, kdfId, aeadId, new byte[0]);
	}

	public KeySchedule(Mode mode, KemId kemId, KdfId kdfId, AeadId aeadId, byte[] info)
	{
		this.mode = Objects.requireNonNull(mode, "mode");
		this.kemId = Objects.requireNonNull(kemId, "kemId");
		this.kdfId = Objects.requireNonNull(kdfId, "kdfId");
		this.aeadId = Objects.requireNonNull(aeadId, "aeadId");
		this.info = Objects.requireNonNull(info, "info");
	}

	public Result executeKeySchedule(SecretKey sharedSecret)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
	{
		byte[] suiteId = ByteEncoding.concat(HPKE, kemId.getIdAsI2osp2Bytes(), kdfId.getIdAsI2osp2Bytes(),
				aeadId.getIdAsI2osp2Bytes());

		KDF kdfContext = kdfId.toKdf();
		Extract pskIdHashSpec = HKDFParameterSpec.ofExtract().addIKM(HPKE_V1).addIKM(suiteId).addIKM(PSK_ID_HASH)
				.addIKM(mode.getPskId()).extractOnly();
		byte[] pskIdHash = kdfContext.deriveData(pskIdHashSpec);

		Extract infoHashSpec = HKDFParameterSpec.ofExtract().addIKM(HPKE_V1).addIKM(suiteId).addIKM(INFO_HASH)
				.addIKM(info).extractOnly();
		byte[] infoHash = kdfContext.deriveData(infoHashSpec);

		byte[] keyScheduleContext = ByteEncoding.concat(mode.getValueAsI2osp1Byte(), pskIdHash, infoHash);

		KDF kdf = kdfId.toKdf();
		Extract secretXSpec = mode.withPsk(HKDFParameterSpec.ofExtract().addIKM(HPKE_V1).addIKM(suiteId).addIKM(SECRET))
				.addSalt(sharedSecret).extractOnly();
		SecretKey secretX = kdf.deriveKey("Generic", secretXSpec);

		byte[] keyInfo = ByteEncoding.concat(aeadId.getKeyLengthAsI2osp2Bytes(), HPKE_V1, suiteId, KEY,
				keyScheduleContext);
		Expand keySpec = HKDFParameterSpec.expandOnly(secretX, keyInfo, aeadId.getKeyLength());

		byte[] baseNonceInfo = ByteEncoding.concat(aeadId.getIvLengthAsI2osp2Bytes(), HPKE_V1, suiteId, BASE_NONCE,
				keyScheduleContext);
		Expand baseNonceSpec = HKDFParameterSpec.expandOnly(secretX, baseNonceInfo, aeadId.getIvLength());

		SecretKey key = kdf.deriveKey(aeadId.getKeyAlgorithm(), keySpec);
		byte[] baseNonce = kdf.deriveData(baseNonceSpec);

		return new Result(key, baseNonce);
	}
}

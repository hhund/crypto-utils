package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import javax.crypto.KDF;

public enum KdfId
{
	HKDF_SHA256(0x0001, "HKDF-SHA256"), HKDF_SHA384(0x0002, "HKDF-SHA384"), HKDF_SHA512(0x0003, "HKDF-SHA512");

	private final int id;
	private final String algorithm;

	KdfId(int id, String algorithm)
	{
		this.algorithm = algorithm;
		this.id = id;
	}

	public int getId()
	{
		return id;
	}

	public byte[] getIdAsI2osp2Bytes()
	{
		return ByteEncoding.i2osp2(id);
	}

	public String getAlgorithm()
	{
		return algorithm;
	}

	public KDF toKdf() throws NoSuchAlgorithmException
	{
		return KDF.getInstance(algorithm);
	}

	public static KdfId from(byte[] value)
	{
		Objects.requireNonNull(value, "value");
		if (value.length != 2)
			throw new IllegalArgumentException("value.length != 2");

		int kdfId = ByteEncoding.os2ip(value);

		if (HKDF_SHA256.id == kdfId)
			return HKDF_SHA256;
		else if (HKDF_SHA384.id == kdfId)
			return HKDF_SHA384;
		else if (HKDF_SHA512.id == kdfId)
			return HKDF_SHA512;
		else
			throw new IllegalArgumentException("KdfId not supported");
	}
}
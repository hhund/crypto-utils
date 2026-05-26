package de.hsheilbronn.mi.utils.crypto.hpke;

import java.util.Objects;

/**
 * length(exp) = 1024 * 2^exp for exp ∈ [0, 15]
 */
public enum ChunkLength
{
	KiB_1, KiB_2, KiB_4, KiB_8, KiB_16, KiB_32, KiB_64, KiB_128, KiB_256, KiB_512, MiB_1, MiB_2, MiB_4, MiB_8, MiB_16, MiB_32;

	public static final int BASE = 1024;

	public int getLength()
	{
		return BASE << ordinal();
	}

	public byte[] getExponentAsI2osp1Byte()
	{
		return ByteEncoding.i2osp1(ordinal());
	}

	public static ChunkLength from(byte[] value) throws IllegalArgumentException
	{
		Objects.requireNonNull(value, "value");
		if (value.length != 1)
			throw new IllegalArgumentException("value.length not 1");

		long exponent = ByteEncoding.os2ip(value);

		if (exponent > ChunkLength.values().length - 1)
			throw new IllegalArgumentException("Chunk length exponent not supported");

		return ChunkLength.values()[(int) exponent];
	}
}

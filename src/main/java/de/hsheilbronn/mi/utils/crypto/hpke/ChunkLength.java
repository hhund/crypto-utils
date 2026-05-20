package de.hsheilbronn.mi.utils.crypto.hpke;

import java.util.Objects;

/**
 * size(exp) = 1024 * 2^exp for exp ∈ [0, 15]
 */
public enum ChunkLength
{
	KiB_1(0), KiB_2(1), KiB_4(2), KiB_8(3), KiB_16(4), KiB_32(5), KiB_64(6), KiB_128(7), KiB_256(8), KiB_512(9), MiB_1(
			10), MiB_2(11), MiB_4(12), MiB_8(13), MiB_16(14), MiB_32(15);

	private static final int BASE = 1024;

	private final int exponent;
	private final int length;

	ChunkLength(int exponent)
	{
		this.exponent = exponent;
		this.length = BASE << exponent;
	}

	public int length()
	{
		return length;
	}

	public byte[] getExponentAsI2osp1Byte()
	{
		return ByteEncoding.i2osp1(exponent);
	}

	public static ChunkLength from(byte[] value)
	{
		Objects.requireNonNull(value, "value");
		if (value.length != 1)
			throw new IllegalArgumentException("value.length != 1");

		int exponent = ByteEncoding.os2ip(value);

		return switch (exponent)
		{
			case 0 -> KiB_1;
			case 1 -> KiB_2;
			case 2 -> KiB_4;
			case 3 -> KiB_8;
			case 4 -> KiB_16;
			case 5 -> KiB_32;
			case 6 -> KiB_64;
			case 7 -> KiB_128;
			case 8 -> KiB_256;
			case 9 -> KiB_512;

			case 10 -> MiB_1;
			case 11 -> MiB_2;
			case 12 -> MiB_4;
			case 13 -> MiB_8;
			case 14 -> MiB_16;
			case 15 -> MiB_32;

			default -> throw new IllegalArgumentException("Chunk length exponent not supported");
		};
	}
}

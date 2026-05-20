package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

public final class ByteEncoding
{
	private ByteEncoding()
	{
	}

	public static byte[] i2osp1(int value)
	{
		Objects.requireNonNull(value, "value");

		if (value >= 256)
			throw new IllegalArgumentException("value >= 256");

		return new byte[] { (byte) value };
	}

	public static byte[] i2osp2(int value)
	{
		Objects.requireNonNull(value, "value");

		if (value >= 65_535)
			throw new IllegalArgumentException("value >= 65535");

		byte[] output = new byte[2];
		output[0] = (byte) (value >>> 8);
		output[1] = (byte) value;
		return output;
	}

	public static int os2ip(byte[] input)
	{
		Objects.requireNonNull(input, "input");

		if (input.length > 4)
			throw new IllegalArgumentException("input.length > 4");
		if (input.length == 0)
			return 0;

		int value = 0;
		for (int j = 0; j < input.length; j++)
			value |= (input[j] & 0xff) << (8 * (input.length - 1 - j));
		return value;
	}

	public static byte[] concat(byte[]... bytes)
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		Arrays.stream(bytes).forEach(out::writeBytes);
		return out.toByteArray();
	}


	public static void expectRead(int expected, int actual) throws IOException
	{
		if (actual < expected)
			throw new IOException("Truncated stream");
	}

	public static void throwIfTruncated(int value) throws IOException
	{
		if (value < 0)
			throw new IOException("Truncated stream");
	}
}

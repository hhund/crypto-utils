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

	/**
	 * @param value
	 *            >= 0 and <= 255
	 * @return encoded value
	 * @throws IllegalArgumentException
	 *             if <b>value</b> &lt; 0 or > 255
	 */
	public static byte[] i2osp1(int value)
	{
		if (value < 0 || value > 0xFF)
			throw new IllegalArgumentException("value < 0 || value > 255");

		return new byte[] { (byte) value };
	}

	/**
	 * @param value
	 *            >= 0 and <= 65535
	 * @return encoded value
	 * @throws IllegalArgumentException
	 *             if <b>value</b> &lt; 0 or > 65535
	 */
	public static byte[] i2osp2(int value)
	{
		if (value < 0 || value > 0xFFFF)
			throw new IllegalArgumentException("value < 0 || value > 65535");

		byte[] output = new byte[2];
		output[0] = (byte) (value >>> 8);
		output[1] = (byte) value;
		return output;
	}

	/**
	 * @param input
	 *            not <code>null</code>, length &lt; 1 or > 4
	 * @return decoded value
	 * @throw {@link IllegalArgumentException} if <b>input</b> length &lt; 1 or > 4
	 */
	public static long os2ip(byte[] input)
	{
		Objects.requireNonNull(input, "input");

		if (input.length < 1 || input.length > 4)
			throw new IllegalArgumentException("input.length < 1 || input.length > 4");

		long value = 0;
		for (int j = 0; j < input.length; j++)
			value |= ((long) input[j] & 0xff) << (8 * (input.length - 1 - j));
		return value;
	}

	public static byte[] concat(byte[]... bytes)
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		Arrays.stream(bytes).forEach(out::writeBytes);
		return out.toByteArray();
	}

	/**
	 * @param expected
	 *            >= 0
	 * @param actual
	 * @throws IllegalArgumentException
	 *             if <b>expected</b> &lt; 0
	 * @throws IOException
	 *             if <b>actual</b> &lt; <b>expected</b>
	 */
	public static void expectRead(int expected, int actual) throws IOException
	{
		if (expected < 0)
			throw new IllegalArgumentException("expected < 0");

		if (actual < expected)
			throw new IOException("Truncated stream");
	}

	/**
	 * @param value
	 * @throws IOException
	 *             if <b>value</b> &lt;0 or >255
	 */
	public static void throwIfTruncated(int value) throws IOException
	{
		if (value < 0)
			throw new IOException("Truncated stream");

		if (value > 0xFF)
			throw new IOException("value > 255");
	}
}

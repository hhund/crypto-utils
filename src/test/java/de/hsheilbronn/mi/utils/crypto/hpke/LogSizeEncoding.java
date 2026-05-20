package de.hsheilbronn.mi.utils.crypto.hpke;

import org.junit.jupiter.api.Test;

public class LogSizeEncoding
{
	// private static final double BASE_EXP = 10.0; // 1 KiB = 2^10
	//
	// /**
	// * Decode byte (0–255) → size in bytes
	// */
	// public static int decode(byte b)
	// {
	// int u = b & 0xFF;
	//
	// int major = u / 16; // exponent step
	// int minor = u % 16; // interpolation within step
	//
	// double exp = BASE_EXP + major + (minor / 16.0);
	//
	// return (int) Math.round(Math.pow(2.0, exp));
	// }
	//
	// /**
	// * Encode size in bytes → best matching byte (0–255)
	// */
	// public static byte encode(int value)
	// {
	// if (value < 1024)
	// value = 1024;
	//
	// double exp = Math.log(value) / Math.log(2.0);
	//
	// double x = exp - BASE_EXP;
	//
	// int major = (int) Math.floor(x);
	// double frac = x - major;
	//
	// int minor = (int) Math.round(frac * 16.0);
	//
	// if (minor == 16)
	// {
	// minor = 0;
	// major += 1;
	// }
	//
	// if (major < 0)
	// major = 0;
	// if (major > 15)
	// major = 15;
	//
	// int encoded = major * 16 + minor;
	//
	// return (byte) (encoded & 0xFF);
	// }

	// private static final int BASE_EXP = 10; // 1 KiB = 2^10
	//
	// /**
	// * Decode byte (0..255) → size in bytes
	// */
	// public static int decode(byte b)
	// {
	// int u = b & 0xFF;
	//
	// int major = u / 16; // 0..15
	// int minor = u % 16; // 0..15
	//
	// double exp = 10 + major + (minor / 16.0);
	//
	// return (int) Math.round(Math.pow(2.0, exp));
	// }
	//
	// public static byte encode(int value)
	// {
	// byte bestByte = 0;
	// long bestError = Long.MAX_VALUE;
	//
	// for (int i = 0; i <= 255; i++)
	// {
	// byte b = (byte) i;
	//
	// int decoded = decode(b);
	// long error = Math.abs((long) decoded - value);
	//
	// if (error < bestError)
	// {
	// bestError = error;
	// bestByte = b;
	//
	// if (error == 0)
	// {
	// break; // exact match found
	// }
	// }
	// }
	//
	// return bestByte;
	// }

	// public static int decode(byte b)
	// {
	// int u = b & 0xFF;
	//
	// int major = u / 16; // 0..15
	// int minor = u % 16; // 0..15
	//
	// double exp = 10 + major + (minor / 16.0);
	//
	// return (int) Math.round(Math.pow(2.0, exp));
	// }
	//
	// public static byte encode(int value)
	// {
	// double exp = Math.log(value) / Math.log(2.0);
	//
	// int major = (int) Math.floor(exp - 10);
	// double frac = exp - Math.floor(exp);
	//
	// int minor = (int) Math.round(frac * 16);
	//
	// if (minor == 16)
	// {
	// minor = 0;
	// major += 1;
	// }
	//
	// if (major < 0) major = 0;
	// if (major > 15) major = 15;
	//
	// return (byte) (major * 16 + minor);
	// }

	public static int decode(byte b)
	{
		int u = b & 0xFF;

		int region = u / 16;
		int step = u % 16;

		long a = 1L << (10 + region);
		long b2 = 1L << (11 + region);

		double t = step / 16.0;

		return (int) Math.round(a + (b2 - a) * t);
	}

	public static byte encode(int value)
	{
		if (value < 0 || value > 0xFF)
			System.err.println(value);

		if (value < (1L << 10))
			return 0;

		int region = (int) (Math.log(value) / Math.log(2)) - 10;
		if (region < 0)
		{
			System.err.println(region);
			region = 0;
		}
		if (region > 15)
		{
			System.err.println(region);
			region = 15;
		}

		long a = 1L << (10 + region);
		long b2 = 1L << (11 + region);

		double t = (double) (value - a) / (double) (b2 - a);
		if (t < 0)
			t = 0;
		if (t > 1)
			t = 1;

		int step = (int) Math.round(t * 16);

		if (step == 16)
		{
			step = 0;
			region++;
			if (region > 15)
			{
				region = 15;
				step = 15;
			}
		}

		return (byte) (region * 16 + step);

	}

	private static final int BASE = 1024;
	private static final int MIN_EXP = 0;
	private static final int MAX_EXP = 15;

	public static int decodeExp(byte code)
	{
		int exp = code & 0xFF;

		if (exp < MIN_EXP || exp > MAX_EXP)
		{
			throw new IllegalArgumentException("Invalid chunk exponent: " + exp);
		}

		return BASE << exp;
	}

	@Test
	void demo() throws Exception
	{
		// for (int i = 0; i <= 0xFF; i++)
		// {
		// int decoded = decode((byte) i);
		// System.out.println(decoded);
		// byte encoded = encode(decoded);
		// // System.out.printf("%3d -> %8d Bytes | %8.2f KiB | %5.2f MiB -> %02X | %3d%n", i, decoded, decoded /
		// // 1024f,
		// // decoded / 1024 / 1024f, (encoded & 0xFF), (encoded & 0xFF));
		// System.out.printf("%3d\t%8d\t%8.2f\t%5.2f\t%02X\t%3d%n", i, decoded, decoded / 1024f,
		// decoded / 1024 / 1024f, (encoded & 0xFF), (encoded & 0xFF));
		// }

		for (int i = MIN_EXP; i <= MAX_EXP; i++)
		{
			int decode = decodeExp((byte) i);
			System.out.printf("%02X -> %8d Byte | %8.2f KiB | %5.2f MiB%n", i % 0xFF, decode, decode / 1024f,
					decode / 1024 / 1024f);
		}
	}
}

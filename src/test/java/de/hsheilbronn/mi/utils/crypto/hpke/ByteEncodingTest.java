package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.io.IOException;

import org.junit.jupiter.api.Test;

public class ByteEncodingTest
{
	@Test
	void testI2osp1() throws Exception
	{
		IllegalArgumentException e = assertThrowsExactly(IllegalArgumentException.class,
				() -> ByteEncoding.i2osp1(Integer.MIN_VALUE));
		assertEquals("value < 0 || value > 255", e.getMessage());
		e = assertThrowsExactly(IllegalArgumentException.class, () -> ByteEncoding.i2osp1(-1));
		assertEquals("value < 0 || value > 255", e.getMessage());

		byte[] b00 = ByteEncoding.i2osp1(0x00);
		assertArrayEquals(new byte[1], b00);
		byte[] b01 = ByteEncoding.i2osp1(0x01);
		assertArrayEquals(new byte[] { (byte) 0x01 }, b01);
		byte[] bFF = ByteEncoding.i2osp1(0xFF);
		assertArrayEquals(new byte[] { (byte) 0xFF }, bFF);

		e = assertThrowsExactly(IllegalArgumentException.class, () -> ByteEncoding.i2osp1(0xFF + 1));
		assertEquals("value < 0 || value > 255", e.getMessage());
		e = assertThrowsExactly(IllegalArgumentException.class, () -> ByteEncoding.i2osp1(Integer.MAX_VALUE));
		assertEquals("value < 0 || value > 255", e.getMessage());
	}

	@Test
	void testI2osp2() throws Exception
	{
		IllegalArgumentException e = assertThrowsExactly(IllegalArgumentException.class,
				() -> ByteEncoding.i2osp2(Integer.MIN_VALUE));
		assertEquals("value < 0 || value > 65535", e.getMessage());
		e = assertThrowsExactly(IllegalArgumentException.class, () -> ByteEncoding.i2osp2(-1));
		assertEquals("value < 0 || value > 65535", e.getMessage());

		byte[] b0000 = ByteEncoding.i2osp2(0x0000);
		assertArrayEquals(new byte[2], b0000);
		byte[] b0001 = ByteEncoding.i2osp2(0x0001);
		assertArrayEquals(new byte[] { (byte) 0x00, (byte) 0x01 }, b0001);
		byte[] bFFFF = ByteEncoding.i2osp2(0xFFFF);
		assertArrayEquals(new byte[] { (byte) 0xFF, (byte) 0xFF }, bFFFF);

		e = assertThrowsExactly(IllegalArgumentException.class, () -> ByteEncoding.i2osp2(0xFFFF + 1));
		assertEquals("value < 0 || value > 65535", e.getMessage());
		e = assertThrowsExactly(IllegalArgumentException.class, () -> ByteEncoding.i2osp2(Integer.MAX_VALUE));
		assertEquals("value < 0 || value > 65535", e.getMessage());
	}

	@Test
	void testOs2ip() throws Exception
	{
		assertThrowsExactly(NullPointerException.class, () -> ByteEncoding.os2ip(null));

		IllegalArgumentException e = assertThrowsExactly(IllegalArgumentException.class,
				() -> ByteEncoding.os2ip(new byte[0]));
		assertEquals("input.length < 1 || input.length > 4", e.getMessage());

		long i1_00 = ByteEncoding.os2ip(new byte[1]);
		assertEquals(0x00, i1_00);
		long i1_01 = ByteEncoding.os2ip(new byte[] { (byte) 0x01 });
		assertEquals(0x01, i1_01);
		long i1_FF = ByteEncoding.os2ip(new byte[] { (byte) 0xFF });
		assertEquals(0xFF, i1_FF);

		long i2_0000 = ByteEncoding.os2ip(new byte[2]);
		assertEquals(0x0000, i2_0000);
		long i2_0001 = ByteEncoding.os2ip(new byte[] { (byte) 0x00, (byte) 0x01 });
		assertEquals(0x0001, i2_0001);
		long i2_FFFF = ByteEncoding.os2ip(new byte[] { (byte) 0xFF, (byte) 0xFF });
		assertEquals(0xFFFF, i2_FFFF);

		long i3_000000 = ByteEncoding.os2ip(new byte[3]);
		assertEquals(0x000000, i3_000000);
		long i3_000001 = ByteEncoding.os2ip(new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x01 });
		assertEquals(0x000001, i3_000001);
		long i3_FFFFFF = ByteEncoding.os2ip(new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF });
		assertEquals(0xFFFFFF, i3_FFFFFF);

		long i4_00000000 = ByteEncoding.os2ip(new byte[4]);
		assertEquals(0x000000, i4_00000000);
		long i4_00000001 = ByteEncoding.os2ip(new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01 });
		assertEquals(0x000001, i4_00000001);
		long i4_FFFFFFFF = ByteEncoding.os2ip(new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF });
		assertEquals(0xFFFFFFFFL, i4_FFFFFFFF);

		e = assertThrowsExactly(IllegalArgumentException.class, () -> ByteEncoding.os2ip(new byte[5]));
		assertEquals("input.length < 1 || input.length > 4", e.getMessage());
	}

	@Test
	void testConcat() throws Exception
	{
		assertThrowsExactly(NullPointerException.class, () -> ByteEncoding.concat((byte[]) null));
		assertThrowsExactly(NullPointerException.class, () -> ByteEncoding.concat(new byte[0], (byte[]) null));
		assertThrowsExactly(NullPointerException.class,
				() -> ByteEncoding.concat(new byte[0], (byte[]) null, new byte[0]));

		assertArrayEquals(new byte[0], ByteEncoding.concat(new byte[0]));
		assertArrayEquals(new byte[0], ByteEncoding.concat(new byte[0], new byte[0]));
		assertArrayEquals(new byte[1], ByteEncoding.concat(new byte[0], new byte[1]));
		assertArrayEquals(new byte[1], ByteEncoding.concat(new byte[1], new byte[0]));
		assertArrayEquals(new byte[2], ByteEncoding.concat(new byte[1], new byte[1]));
		assertArrayEquals(new byte[] { (byte) 0x01, (byte) 0x02, (byte) 0x03 }, ByteEncoding
				.concat(new byte[] { (byte) 0x01 }, new byte[] { (byte) 0x02 }, new byte[] { (byte) 0x03 }));
	}

	@Test
	void testExpectRead() throws Exception
	{
		assertDoesNotThrow(() -> ByteEncoding.expectRead(0, 0));
		IOException e = assertThrowsExactly(IOException.class, () -> ByteEncoding.expectRead(1, 0));
		assertEquals(e.getMessage(), "Truncated stream");
		e = assertThrowsExactly(IOException.class, () -> ByteEncoding.expectRead(1, -1));
		assertEquals(e.getMessage(), "Truncated stream");
		IllegalArgumentException i = assertThrowsExactly(IllegalArgumentException.class,
				() -> ByteEncoding.expectRead(-1, 0));
		assertEquals(i.getMessage(), "expected < 0");
	}

	@Test
	void testThrowIfTruncated() throws Exception
	{
		IOException e = assertThrowsExactly(IOException.class, () -> ByteEncoding.throwIfTruncated(Integer.MIN_VALUE));
		assertEquals(e.getMessage(), "Truncated stream");
		e = assertThrowsExactly(IOException.class, () -> ByteEncoding.throwIfTruncated(-1));
		assertEquals(e.getMessage(), "Truncated stream");

		assertDoesNotThrow(() -> ByteEncoding.throwIfTruncated(0));
		assertDoesNotThrow(() -> ByteEncoding.throwIfTruncated(1));
		assertDoesNotThrow(() -> ByteEncoding.throwIfTruncated(0xFF));

		e = assertThrowsExactly(IOException.class, () -> ByteEncoding.throwIfTruncated(Integer.MAX_VALUE));
		assertEquals(e.getMessage(), "value > 255");
	}
}

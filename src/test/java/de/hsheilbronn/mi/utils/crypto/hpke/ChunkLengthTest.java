package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.util.EnumSet;

import org.junit.jupiter.api.Test;

public class ChunkLengthTest
{
	@Test
	void testEncodeDecode() throws Exception
	{
		EnumSet.allOf(ChunkLength.class).forEach(cl ->
		{
			byte[] encoded = cl.getExponentAsI2osp1Byte();
			assertNotNull(encoded);
			ChunkLength decoded = ChunkLength.from(encoded);
			assertNotNull(decoded);
			assertEquals(cl, decoded);
		});
	}

	@Test
	void testGetLenght() throws Exception
	{
		ChunkLength[] values = ChunkLength.values();
		assertEquals(16, values.length);

		for (int i = 0; i < values.length; i++)
		{
			int expectedLength = (int) (ChunkLength.BASE * Math.pow(2, i));
			assertEquals(expectedLength, values[i].getLength());
		}
	}

	@Test
	void testFromInvalid() throws Exception
	{
		IllegalArgumentException e = assertThrowsExactly(IllegalArgumentException.class,
				() -> ChunkLength.from(new byte[0]));
		assertEquals("value.length != 1", e.getMessage());
		e = assertThrowsExactly(IllegalArgumentException.class,
				() -> ChunkLength.from(new byte[] { (byte) ChunkLength.values().length }));
		assertEquals("Chunk length exponent not supported", e.getMessage());
		e = assertThrowsExactly(IllegalArgumentException.class, () -> ChunkLength.from(new byte[] { (byte) 0xFF }));
		assertEquals("Chunk length exponent not supported", e.getMessage());
	}
}

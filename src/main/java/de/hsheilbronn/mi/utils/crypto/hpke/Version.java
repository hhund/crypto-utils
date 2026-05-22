package de.hsheilbronn.mi.utils.crypto.hpke;

public enum Version
{
	V1(0x01);

	private final int value;

	Version(int id)
	{
		this.value = id;
	}

	public int getValue()
	{
		return value;
	}

	public byte[] getValueAsI2osp1Byte()
	{
		return ByteEncoding.i2osp1(value);
	}

	public static Version from(byte value)
	{
		int version = value & 0xFF;

		if (V1.value == version)
			return V1;
		else
			throw new IllegalArgumentException("Version not supported");
	}
}

package de.hsheilbronn.mi.utils.crypto.hpke;

import java.util.Arrays;
import java.util.Objects;

public final class Mode
{
	public static final int BASE_VALUE = 0x00;
	public static final int PSK_VALUE = 0x01;

	private final int value;
	private final byte[] pskId;

	protected Mode(int value, byte[] pskId)
	{
		this.value = value;
		this.pskId = pskId;
	}

	/**
	 * @return mode 0
	 */
	public static Mode base()
	{
		return new Mode(BASE_VALUE, new byte[0]);
	}

	/**
	 * @param pskId
	 *            not <code>null</code>, pskId.length > 0
	 * @return mode 1
	 */
	public static Mode psk(byte[] pskId)
	{
		Objects.requireNonNull(pskId, "pskId");
		if (pskId.length <= 0)
			throw new IllegalArgumentException("pskId.length <= 0");

		return new Mode(PSK_VALUE, pskId);
	}

	public byte[] getValueAsI2osp1Byte()
	{
		return ByteEncoding.i2osp1(value);
	}

	public byte[] getPskId()
	{
		return pskId.clone();
	}

	@Override
	public int hashCode()
	{
		final int prime = 31;
		int result = 1;
		result = prime * result + Objects.hash(value);
		result = prime * result + Arrays.hashCode(pskId);
		return result;
	}

	@Override
	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Mode other = (Mode) obj;
		return value == other.value && Arrays.equals(pskId, other.pskId);
	}

	@Override
	public String toString()
	{
		return Integer.toString(value);
	}

	public boolean isPsk()
	{
		return PSK_VALUE == value;
	}

	/**
	 * @param value
	 *            <code>0x00</code> or <code>0x01</code>
	 * @param pskId
	 *            <code>null</code> if <b>value</b> = <code>0x00</code>, not <code>null</code> and length > 0 if
	 *            <b>value</b> = <code>0x01</code>
	 * @return HPKE mode
	 * @throws IllegalArgumentException
	 *             given <b>value</b> and <b>pskId</b> combination is unexpected or <b>value</b> is not supported
	 */
	public static Mode from(byte value, byte[] pskId) throws IllegalArgumentException
	{
		if (BASE_VALUE == value && pskId == null)
			return Mode.base();
		else if (PSK_VALUE == value && pskId != null)
			return Mode.psk(pskId);
		else
			throw new IllegalArgumentException("Mode not supported");
	}
}
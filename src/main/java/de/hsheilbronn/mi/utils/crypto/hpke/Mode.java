package de.hsheilbronn.mi.utils.crypto.hpke;

import java.util.Arrays;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec.Builder;

public final class Mode
{
	public static final int BASE_VALUE = 0x00;
	public static final int PSK_VALUE = 0x01;

	private final int value;
	private final byte[] pskId;
	private final SecretKey psk;

	protected Mode(int value, byte[] pskId, SecretKey psk)
	{
		this.value = value;
		this.pskId = pskId;
		this.psk = psk;
	}

	/**
	 * @return mode 0
	 */
	public static Mode base()
	{
		return new Mode(BASE_VALUE, new byte[0], null);
	}

	/**
	 * @param pskId
	 *            not <code>null</code>, pskId.length > 0
	 * @param psk
	 *            not <code>null</code>
	 * @return mode 1
	 */
	public static Mode psk(byte[] pskId, SecretKey psk)
	{
		Objects.requireNonNull(pskId, "pskId");
		if (pskId.length <= 0)
			throw new IllegalArgumentException("pskId.length <= 0");
		Objects.requireNonNull(psk, "psk");

		return new Mode(PSK_VALUE, pskId, psk);
	}

	/**
	 * @param pskId
	 *            not <code>null</code>, pskId.length > 0
	 * @param pskProvider
	 *            not <code>null</code>
	 * @return mode 1
	 * @throws KeyNotFoundException
	 *             if the <b>pskProvider</b> has no key for <b>pskId</b>
	 */
	public static Mode psk(byte[] pskId, PreSharedKeyProvider pskProvider) throws KeyNotFoundException
	{
		Objects.requireNonNull(pskId, "pskId");
		if (pskId.length <= 0)
			throw new IllegalArgumentException("pskId.length <= 0");
		Objects.requireNonNull(pskProvider, "pskProvider");

		SecretKey psk = pskProvider.retrieve(pskId);

		return new Mode(PSK_VALUE, pskId, psk);
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
		result = prime * result + Arrays.hashCode(pskId);
		result = prime * result + Objects.hash(value);
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
		return Arrays.equals(pskId, other.pskId) && value == other.value;
	}

	@Override
	public String toString()
	{
		return Integer.toString(value);
	}

	public Builder withPsk(Builder secretXSpecBuilder)
	{
		if (psk != null)
			return secretXSpecBuilder.addIKM(psk);
		else
			return secretXSpecBuilder;
	}

	public boolean isPsk()
	{
		return PSK_VALUE == value;
	}

	/**
	 * @param value
	 *            <code>0x00</code> or <code>0x01</code>
	 * @param pskId
	 *            <code>null</code> if <b>mode</b> = <code>0x00</code> else not <code>null</code> and length =
	 *            {@value Header#PSK_ID_LENGTH}
	 * @param pskProvider
	 *            not <code>null</code>
	 * @return HPKE mode
	 * @throws KeyNotFoundException
	 *             if no PSK could be found for the given <b>pskId</b>
	 */
	public static Mode from(byte value, byte[] pskId, PreSharedKeyProvider pskProvider) throws KeyNotFoundException
	{
		Objects.requireNonNull(pskProvider, "pskProvider");

		if (BASE_VALUE == value)
			return Mode.base();
		else if (PSK_VALUE == value)
		{
			Objects.requireNonNull(pskId, "pskId");
			if (pskId.length != Header.PSK_ID_LENGTH)
				throw new IllegalArgumentException("pskId.length != " + Header.PSK_ID_LENGTH);
			return Mode.psk(pskId, pskProvider.retrieve(pskId));
		}
		else
			throw new IllegalArgumentException("Mode not supported");
	}
}
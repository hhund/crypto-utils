package de.hsheilbronn.mi.utils.crypto.hpke;

import java.util.HexFormat;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

/**
 * {@link Function} to retrieve the a pre-shared-key (psk) {@link SecretKey} for a given <b>pskId</b>
 */
@FunctionalInterface
public interface PskProvider
{
	SecretKey retrieve(byte[] pskId) throws KeyNotFoundException;

	static PskProvider fromMap(Map<byte[], SecretKey> map)
	{
		return pskId ->
		{
			SecretKey key = map.get(pskId);

			if (key != null)
				return key;
			else
				throw new KeyNotFoundException("No PSK with ID " + HexFormat.of().formatHex(pskId));
		};
	}
}

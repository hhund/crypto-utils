package de.hsheilbronn.mi.utils.crypto.hpke;

import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

/**
 * {@link Function} to retrieve the a pre-shared-key (psk) {@link SecretKey} for a given <b>pskId</b>
 */
@FunctionalInterface
public interface PreSharedKeyProvider extends KeyProvider<SecretKey>
{
	static PreSharedKeyProvider of()
	{
		return KeyProvider.<SecretKey> of(PSK)::retrieve;
	}

	static PreSharedKeyProvider of(byte[] pskId, SecretKey psk)
	{
		return KeyProvider.of(PSK, pskId, psk)::retrieve;
	}

	static PreSharedKeyProvider of(Map<byte[], SecretKey> map)
	{
		return KeyProvider.of(PSK, map)::retrieve;
	}
}

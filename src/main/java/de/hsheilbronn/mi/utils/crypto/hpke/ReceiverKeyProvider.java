package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.PrivateKey;
import java.util.Map;
import java.util.function.Function;

/**
 * {@link Function} to retrieve the receiver {@link PrivateKey} for a given <b>receiverKeyId</b>
 */
@FunctionalInterface
public interface ReceiverKeyProvider extends KeyProvider<PrivateKey>
{
	static ReceiverKeyProvider of()
	{
		return KeyProvider.<PrivateKey> of(RECEIVER_KEY_ID)::retrieve;
	}

	static ReceiverKeyProvider of(byte[] pskId, PrivateKey psk)
	{
		return KeyProvider.of(RECEIVER_KEY_ID, pskId, psk)::retrieve;
	}

	static ReceiverKeyProvider of(Map<byte[], PrivateKey> map)
	{
		return KeyProvider.of(RECEIVER_KEY_ID, map)::retrieve;
	}
}

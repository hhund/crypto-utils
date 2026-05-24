package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.PrivateKey;
import java.util.Map;
import java.util.function.Function;

/**
 * {@link Function} to retrieve the receiver {@link PrivateKey} for a given <b>receiverKeyId</b>
 */
@FunctionalInterface
public interface ReceiverPrivateKeyProvider extends KeyProvider<PrivateKey>
{
	static ReceiverPrivateKeyProvider of()
	{
		return KeyProvider.<PrivateKey> of(RECEIVER_KEY_ID)::retrieve;
	}

	static ReceiverPrivateKeyProvider of(byte[] receiverKeyId, PrivateKey receiverKey)
	{
		return KeyProvider.of(RECEIVER_KEY_ID, receiverKeyId, receiverKey)::retrieve;
	}

	static ReceiverPrivateKeyProvider of(Map<byte[], PrivateKey> map)
	{
		return KeyProvider.of(RECEIVER_KEY_ID, map)::retrieve;
	}
}

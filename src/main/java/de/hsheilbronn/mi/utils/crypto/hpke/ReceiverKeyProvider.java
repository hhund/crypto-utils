package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.PrivateKey;
import java.util.function.Function;

/**
 * {@link Function} to retrieve the receiver {@link PrivateKey} for a given <b>receiverKeyId</b>
 */
@FunctionalInterface
public interface ReceiverKeyProvider
{
	PrivateKey retrieve(byte[] receiverKeyId) throws KeyNotFoundException;
}

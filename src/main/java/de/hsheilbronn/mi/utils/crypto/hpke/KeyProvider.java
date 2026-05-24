package de.hsheilbronn.mi.utils.crypto.hpke;

import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.stream.Collectors;

@FunctionalInterface
interface KeyProvider<K extends Key>
{
	public static final String RECEIVER_KEY_ID = "ReceiverKeyId";
	public static final String PSK = "PSK";

	K retrieve(byte[] id) throws KeyNotFoundException;

	static <K extends Key> KeyProvider<K> of(String type)
	{
		return i ->
		{
			throw notFound(type, i);
		};
	}

	static <K extends Key> KeyProvider<K> of(String type, byte[] id, K key)
	{
		Objects.requireNonNull(id, "id");
		Objects.requireNonNull(key, "key");

		return i ->
		{
			if (Arrays.equals(i, id))
				return key;
			else
				throw notFound(type, i);
		};
	}

	static <K extends Key> KeyProvider<K> of(String type, Map<byte[], K> map)
	{
		Objects.requireNonNull(map, "map");

		final Map<ByteBuffer, K> cache = map.entrySet().stream().collect(
				Collectors.toMap(e -> ByteBuffer.wrap(e.getKey().clone()).asReadOnlyBuffer(), Entry::getValue));

		return i ->
		{
			if (i == null)
				throw notFound(type, null);

			K key = cache.get(ByteBuffer.wrap(i));

			if (key != null)
				return key;
			else
				throw notFound(type, i);
		};
	}

	static KeyNotFoundException notFound(String type, byte[] id)
	{
		return new KeyNotFoundException(
				type + " with ID " + (id != null ? HexFormat.of().formatHex(id) : "null") + " not found");
	}
}

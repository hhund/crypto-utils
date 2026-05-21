package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Map;
import java.util.stream.Stream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class KeyProviderTest
{
	private static final byte[] PSK_ID_1 = Sha256
			.digest("Test Pre Shared Key ID 1".getBytes(StandardCharsets.US_ASCII));
	private static final byte[] PSK_ID_2 = Sha256
			.digest("Test Pre Shared Key ID 2".getBytes(StandardCharsets.US_ASCII));
	private static final SecretKey PSK_1 = new SecretKeySpec(
			new byte[] { 'T', 'e', 's', 't', ' ', 'P', 'S', 'K', ' ', '1' }, "Generic");
	private static final SecretKey PSK_2 = new SecretKeySpec(
			new byte[] { 'T', 'e', 's', 't', ' ', 'P', 'S', 'K', ' ', '2' }, "Generic");

	private static final KeyPairGenerator RK_GENERATOR = KeyPairGeneratorFactory.rsa1024().initialize();

	private static final byte[] RK_ID_1 = Sha256.digest("Test Receiver Key ID 1".getBytes(StandardCharsets.US_ASCII));
	private static final PrivateKey RK_1 = RK_GENERATOR.generateKeyPair().getPrivate();
	private static final byte[] RK_ID_2 = Sha256.digest("Test Receiver Key ID 2".getBytes(StandardCharsets.US_ASCII));
	private static final PrivateKey RK_2 = RK_GENERATOR.generateKeyPair().getPrivate();

	private static Stream<Arguments> forTestOf()
	{
		return Stream.of(Arguments.of(PreSharedKeyProvider.of(), KeyProvider.PSK, PSK_ID_1, PSK_ID_2),
				Arguments.of(ReceiverKeyProvider.of(), KeyProvider.RECEIVER_KEY_ID, RK_ID_1, RK_ID_2));
	}

	@ParameterizedTest
	@MethodSource("forTestOf")
	<K extends Key> void testOf(KeyProvider<K> provider, String type, byte[] id1, byte[] id2) throws Exception
	{
		testNotFound(provider, type, id1);
		testNotFound(provider, type, id2);
		testNotFound(provider, type, new byte[0]);
		testNotFound(provider, type, null);
	}

	private static Stream<Arguments> forTestOf1()
	{
		return Stream.of(
				Arguments.of(PreSharedKeyProvider.of(PSK_ID_1, PSK_1), KeyProvider.PSK, PSK_ID_1, PSK_1, PSK_ID_2),
				Arguments.of(ReceiverKeyProvider.of(RK_ID_1, RK_1), KeyProvider.RECEIVER_KEY_ID, RK_ID_1, RK_1,
						RK_ID_2));
	}

	@ParameterizedTest
	@MethodSource("forTestOf1")
	<K extends Key> void testOf1(KeyProvider<K> provider, String type, byte[] id1, K key1, byte[] id2) throws Exception
	{
		testFound(provider, id1, key1);

		testNotFound(provider, type, id2);
		testNotFound(provider, type, new byte[0]);
		testNotFound(provider, type, null);
	}

	private static Stream<Arguments> forTestOf2()
	{
		return Stream.of(
				Arguments.of(PreSharedKeyProvider.of(Map.of(PSK_ID_1, PSK_1, PSK_ID_2, PSK_2)), KeyProvider.PSK,
						PSK_ID_1, PSK_1, PSK_ID_2, PSK_2),
				Arguments.of(ReceiverKeyProvider.of(Map.of(RK_ID_1, RK_1, RK_ID_2, RK_2)), KeyProvider.RECEIVER_KEY_ID,
						RK_ID_1, RK_1, RK_ID_2, RK_2));
	}

	@ParameterizedTest
	@MethodSource("forTestOf2")
	<K extends Key> void testOf2(KeyProvider<K> provider, String type, byte[] id1, K key1, byte[] id2, K key2)
			throws Exception
	{
		testFound(provider, id1, key1);
		testFound(provider, id2, key2);

		testNotFound(provider, type, new byte[0]);
		testNotFound(provider, type, null);
	}

	private <K extends Key> void testFound(KeyProvider<K> provider, byte[] pskId, K expected)
			throws KeyNotFoundException
	{
		Key k = provider.retrieve(pskId);
		assertNotNull(k);
		assertEquals(expected, k);
	}

	private void testNotFound(KeyProvider<?> provider, String type, byte[] pskId)
	{
		KeyNotFoundException e = assertThrowsExactly(KeyNotFoundException.class, () -> provider.retrieve(pskId));
		assertEquals(KeyProvider.notFound(type, pskId).getMessage(), e.getMessage());
	}
}

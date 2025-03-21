package de.hsheilbronn.mi.utils.crypto.kem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.EnumSet;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.kem.AbstractKemAesGcm.Variant;
import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class KemAesGcmTest
{
	private static final String TEST_DATA = """
			Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce finibus risus et lacus vestibulum sodales. Aliquam pretium efficitur ipsum, vitae faucibus nibh mollis lobortis. Vivamus feugiat finibus lorem posuere volutpat. Sed sed pulvinar velit. Fusce ac viverra mauris. In hac habitasse platea dictumst. Nulla porta, eros id maximus aliquam, nibh ante ullamcorper mi, in fringilla tellus est eu libero. Praesent mattis, lacus non consequat euismod, risus dui gravida dui, eget volutpat nulla felis vitae tellus. Duis imperdiet dignissim ultricies. In hac habitasse platea dictumst. Vestibulum ultricies nisl a magna suscipit scelerisque. Curabitur eget dapibus eros, id aliquam lorem. Donec congue odio nec tortor interdum, non molestie erat interdum. Sed at lacinia tellus, at consequat ligula.
			Aliquam consectetur dui at mollis posuere. Curabitur iaculis dui in imperdiet auctor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas ullamcorper suscipit dictum. Cras eros nisl, dapibus quis porta ut, semper a purus. Proin sodales nunc a tortor pretium, sed tempus risus feugiat. Quisque faucibus sem ante, et sollicitudin massa venenatis vitae. Donec nunc diam, pretium nec turpis a, dapibus elementum dui. Donec leo mi, congue finibus dapibus sed, varius at est. Donec ante nisl, tincidunt eget augue nec, gravida porta enim.
			Quisque molestie efficitur dolor, ac volutpat libero mollis vel. Vestibulum non tortor quis turpis laoreet cursus non eu leo. Praesent pulvinar purus id tristique accumsan. Phasellus efficitur id leo nec tincidunt. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Sed ac blandit augue, eget mollis enim. Proin lacinia risus non nibh egestas, ac interdum risus mattis. Vestibulum eu justo ac nunc viverra venenatis vitae vel velit. Vivamus sagittis aliquam lobortis. Nunc volutpat, metus aliquam finibus placerat, massa mauris venenatis est, et mattis purus leo id libero. Nulla ornare massa erat, et lacinia tortor condimentum quis. In eu tempor arcu, a facilisis urna. Duis ultricies justo mi, nec blandit nisi suscipit sit amet. Nullam sit amet interdum tellus. Vivamus vel enim ligula.
			""";

	private static final record FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory factory,
			int expectedDataEncryptedLength, int expectedNoDataEncryptedLength)
	{
	}

	private static Stream<Arguments> forEncryptDecryptTest()
	{
		Supplier<Stream<FactoryAndExpectedNoDataEncryptedLength>> ecFactories = () -> Stream.of(
				new FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory.secp256r1(), 2269, 95),
				new FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory.secp384r1(), 2301, 127),
				new FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory.secp521r1(), 2337, 163),
				new FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory.x25519(), 2236, 62),
				new FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory.x448(), 2260, 86));

		Supplier<Stream<FactoryAndExpectedNoDataEncryptedLength>> rsaFactories = () -> Stream.of(
				new FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory.rsa1024(), 2332, 158),
				new FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory.rsa2048(), 2460, 286),
				new FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory.rsa3072(), 2588, 414),
				new FactoryAndExpectedNoDataEncryptedLength(KeyPairGeneratorFactory.rsa4096(), 2716, 542));

		return EnumSet.allOf(Variant.class).stream().flatMap(v ->

		Stream.concat(
				ecFactories.get()
						.map(kp -> Arguments.of(new EcDhKemAesGcm(v), kp.factory, kp.expectedDataEncryptedLength,
								kp.expectedNoDataEncryptedLength)),
				rsaFactories.get().map(kp -> Arguments.of(new RsaKemAesGcm(v), kp.factory,
						kp.expectedDataEncryptedLength, kp.expectedNoDataEncryptedLength))));
	}

	@ParameterizedTest
	@MethodSource("forEncryptDecryptTest")
	void encryptDecryptTest(AbstractKemAesGcm kem, KeyPairGeneratorFactory factory, int expectedDataEncryptedLength,
			int expectedNoDataEncryptedLength) throws Exception
	{
		KeyPair keyPair = factory.initialize().generateKeyPair();

		InputStream encrypted = kem.encrypt(new ByteArrayInputStream(TEST_DATA.getBytes(StandardCharsets.UTF_8)),
				keyPair.getPublic());
		assertNotNull(encrypted);

		byte[] encryptedBytes = encrypted.readAllBytes();
		assertNotNull(encryptedBytes);
		assertEquals(expectedDataEncryptedLength, encryptedBytes.length);

		InputStream decrypted = kem.decrypt(new ByteArrayInputStream(encryptedBytes), keyPair.getPrivate());
		assertNotNull(decrypted);

		assertEquals(TEST_DATA, new String(decrypted.readAllBytes(), StandardCharsets.UTF_8));

		InputStream encrypted0 = kem.encrypt(new ByteArrayInputStream(new byte[0]), keyPair.getPublic());
		assertNotNull(encrypted0);

		byte[] encrypted0Bytes = encrypted0.readAllBytes();
		assertNotNull(encrypted0Bytes);
		assertEquals(expectedNoDataEncryptedLength, encrypted0Bytes.length);

		InputStream decrypted0 = kem.decrypt(new ByteArrayInputStream(encrypted0Bytes), keyPair.getPrivate());
		assertNotNull(decrypted0);

		assertEquals(0, decrypted0.readAllBytes().length);
	}

	private static Stream<Arguments> forEncryptDecryptInvalidArguments()
	{
		KeyPair secp256r1 = KeyPairGeneratorFactory.secp256r1().initialize().genKeyPair();
		KeyPair rsa1024 = KeyPairGeneratorFactory.rsa1024().initialize().generateKeyPair();

		return EnumSet.allOf(Variant.class).stream()
				.flatMap(v -> Stream.of(Arguments.of(new EcDhKemAesGcm(v), secp256r1, rsa1024),
						Arguments.of(new RsaKemAesGcm(v), rsa1024, secp256r1)));
	}

	@Test
	void constructorInvalidArguments() throws Exception
	{
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm(null));
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm(null, AbstractKemAesGcm.SECURE_RANDOM));
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm(Variant.AES_128, null));
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm(null, null));

		assertThrowsExactly(NullPointerException.class, () -> new RsaKemAesGcm(null));
		assertThrowsExactly(NullPointerException.class, () -> new RsaKemAesGcm(null, AbstractKemAesGcm.SECURE_RANDOM));
		assertThrowsExactly(NullPointerException.class, () -> new RsaKemAesGcm(Variant.AES_128, null));
		assertThrowsExactly(NullPointerException.class, () -> new RsaKemAesGcm(null, null));
	}

	@ParameterizedTest
	@MethodSource("forEncryptDecryptInvalidArguments")
	void encryptInvalidArguments(AbstractKemAesGcm kem, KeyPair validKeyPair, KeyPair invalidKeyPair) throws Exception
	{
		assertThrowsExactly(NullPointerException.class, () -> kem.encrypt(null, null));
		assertThrowsExactly(NullPointerException.class, () -> kem.encrypt(new ByteArrayInputStream(new byte[0]), null));
		assertThrowsExactly(NullPointerException.class, () -> kem.encrypt(null, validKeyPair.getPublic()));
		assertThrowsExactly(IllegalArgumentException.class,
				() -> kem.encrypt(new ByteArrayInputStream(new byte[0]), invalidKeyPair.getPublic()));
	}

	@ParameterizedTest
	@MethodSource("forEncryptDecryptInvalidArguments")
	void decryptInvalidArguments(AbstractKemAesGcm kem, KeyPair validKeyPair, KeyPair invalidKeyPair) throws Exception
	{
		assertThrowsExactly(NullPointerException.class, () -> kem.decrypt(null, null));
		assertThrowsExactly(NullPointerException.class, () -> kem.decrypt(new ByteArrayInputStream(new byte[0]), null));
		assertThrowsExactly(NullPointerException.class, () -> kem.decrypt(null, validKeyPair.getPrivate()));
		assertThrowsExactly(IllegalArgumentException.class,
				() -> kem.decrypt(new ByteArrayInputStream(new byte[0]), invalidKeyPair.getPrivate()));
	}
}

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

import de.hsheilbronn.mi.utils.crypto.kem.EcDhKemAesGcm.Variant;
import de.hsheilbronn.mi.utils.crypto.keypair.KeyPairGeneratorFactory;

public class EcDhKemAesGcmTest
{
	private static final String TEST_DATA = """
			Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce finibus risus et lacus vestibulum sodales. Aliquam pretium efficitur ipsum, vitae faucibus nibh mollis lobortis. Vivamus feugiat finibus lorem posuere volutpat. Sed sed pulvinar velit. Fusce ac viverra mauris. In hac habitasse platea dictumst. Nulla porta, eros id maximus aliquam, nibh ante ullamcorper mi, in fringilla tellus est eu libero. Praesent mattis, lacus non consequat euismod, risus dui gravida dui, eget volutpat nulla felis vitae tellus. Duis imperdiet dignissim ultricies. In hac habitasse platea dictumst. Vestibulum ultricies nisl a magna suscipit scelerisque. Curabitur eget dapibus eros, id aliquam lorem. Donec congue odio nec tortor interdum, non molestie erat interdum. Sed at lacinia tellus, at consequat ligula.
			Aliquam consectetur dui at mollis posuere. Curabitur iaculis dui in imperdiet auctor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas ullamcorper suscipit dictum. Cras eros nisl, dapibus quis porta ut, semper a purus. Proin sodales nunc a tortor pretium, sed tempus risus feugiat. Quisque faucibus sem ante, et sollicitudin massa venenatis vitae. Donec nunc diam, pretium nec turpis a, dapibus elementum dui. Donec leo mi, congue finibus dapibus sed, varius at est. Donec ante nisl, tincidunt eget augue nec, gravida porta enim.
			Quisque molestie efficitur dolor, ac volutpat libero mollis vel. Vestibulum non tortor quis turpis laoreet cursus non eu leo. Praesent pulvinar purus id tristique accumsan. Phasellus efficitur id leo nec tincidunt. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Sed ac blandit augue, eget mollis enim. Proin lacinia risus non nibh egestas, ac interdum risus mattis. Vestibulum eu justo ac nunc viverra venenatis vitae vel velit. Vivamus sagittis aliquam lobortis. Nunc volutpat, metus aliquam finibus placerat, massa mauris venenatis est, et mattis purus leo id libero. Nulla ornare massa erat, et lacinia tortor condimentum quis. In eu tempor arcu, a facilisis urna. Duis ultricies justo mi, nec blandit nisi suscipit sit amet. Nullam sit amet interdum tellus. Vivamus vel enim ligula.
			""";

	private static Stream<Arguments> forEncryptDecryptTest()
	{
		Supplier<Stream<KeyPairGeneratorFactory>> factories = () -> Stream.of(KeyPairGeneratorFactory.secp256r1(),
				KeyPairGeneratorFactory.secp384r1(), KeyPairGeneratorFactory.secp521r1(),
				KeyPairGeneratorFactory.x25519(), KeyPairGeneratorFactory.x448());

		return EnumSet.allOf(Variant.class).stream().flatMap(v -> factories.get().map(kp -> Arguments.of(v, kp)));
	}

	@ParameterizedTest
	@MethodSource("forEncryptDecryptTest")
	void encryptDecryptTest(Variant variant, KeyPairGeneratorFactory factory) throws Exception
	{
		KeyPair keyPair = factory.initialize().generateKeyPair();

		InputStream encrypted = new EcDhKemAesGcm(variant)
				.encrypt(new ByteArrayInputStream(TEST_DATA.getBytes(StandardCharsets.UTF_8)), keyPair.getPublic());
		assertNotNull(encrypted);

		InputStream decrypted = new EcDhKemAesGcm(variant).decrypt(encrypted, keyPair.getPrivate());
		assertNotNull(decrypted);

		assertEquals(TEST_DATA, new String(decrypted.readAllBytes(), StandardCharsets.UTF_8));
	}

	@Test
	void encryptInvalidArguments() throws Exception
	{
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm(null));
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm().encrypt(null, null));
		assertThrowsExactly(NullPointerException.class,
				() -> new EcDhKemAesGcm().encrypt(new ByteArrayInputStream(new byte[0]), null));
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm().encrypt(null,
				KeyPairGeneratorFactory.secp256r1().initialize().generateKeyPair().getPublic()));
		assertThrowsExactly(IllegalArgumentException.class,
				() -> new EcDhKemAesGcm().encrypt(new ByteArrayInputStream(new byte[0]),
						KeyPairGeneratorFactory.rsa1024().initialize().generateKeyPair().getPublic()));
	}

	@Test
	void decryptInvalidArguments() throws Exception
	{
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm(null));
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm().decrypt(null, null));
		assertThrowsExactly(NullPointerException.class,
				() -> new EcDhKemAesGcm().decrypt(new ByteArrayInputStream(new byte[0]), null));
		assertThrowsExactly(NullPointerException.class, () -> new EcDhKemAesGcm().decrypt(null,
				KeyPairGeneratorFactory.secp256r1().initialize().generateKeyPair().getPrivate()));
		assertThrowsExactly(IllegalArgumentException.class,
				() -> new EcDhKemAesGcm().decrypt(new ByteArrayInputStream(new byte[0]),
						KeyPairGeneratorFactory.rsa1024().initialize().generateKeyPair().getPrivate()));
	}
}

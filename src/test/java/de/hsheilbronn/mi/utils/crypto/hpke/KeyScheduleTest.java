package de.hsheilbronn.mi.utils.crypto.hpke;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.util.HexFormat;
import java.util.stream.Stream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.hsheilbronn.mi.utils.crypto.hpke.KeySchedule.Result;

public class KeyScheduleTest
{
	private static record Rfc9180TestData(String name, Mode mode, KemId kemId, KdfId kdfId, AeadId aeadId,
			PrivateKey skRm, byte[] enc, byte[] sharedSecret, byte[] key, byte[] baseNonce)
	{
		public static Rfc9180TestData withX25519(String name, Mode mode, KemId kemId, KdfId kdfId, AeadId aeadId,
				String skRm, String enc, String sharedSecret, String key, String baseNonce)
		{
			return new Rfc9180TestData(name, mode, kemId, kdfId, aeadId, toX25519PrivateKey(skRm),
					HexFormat.of().parseHex(enc), HexFormat.of().parseHex(sharedSecret), HexFormat.of().parseHex(key),
					HexFormat.of().parseHex(baseNonce));
		}

		private static PrivateKey toX25519PrivateKey(String hex)
		{
			try
			{
				XECPrivateKeySpec spec = new XECPrivateKeySpec(NamedParameterSpec.X25519, HexFormat.of().parseHex(hex));
				return KeyFactory.getInstance("X25519").generatePrivate(spec);
			}
			catch (InvalidKeySpecException | NoSuchAlgorithmException e)
			{
				throw new RuntimeException(e);
			}
		}

		public static Rfc9180TestData withSecp256r1(String name, Mode mode, KemId kemId, KdfId kdfId, AeadId aeadId,
				String skRm, String enc, String sharedSecret, String key, String baseNonce)
		{
			return new Rfc9180TestData(name, mode, kemId, kdfId, aeadId, toEcPrivateKey("secp256r1", skRm),
					HexFormat.of().parseHex(enc), HexFormat.of().parseHex(sharedSecret), HexFormat.of().parseHex(key),
					HexFormat.of().parseHex(baseNonce));
		}

		public static Rfc9180TestData withSecp521r1(String name, Mode mode, KemId kemId, KdfId kdfId, AeadId aeadId,
				String skRm, String enc, String sharedSecret, String key, String baseNonce)
		{
			return new Rfc9180TestData(name, mode, kemId, kdfId, aeadId, toEcPrivateKey("secp521r1", skRm),
					HexFormat.of().parseHex(enc), HexFormat.of().parseHex(sharedSecret), HexFormat.of().parseHex(key),
					HexFormat.of().parseHex(baseNonce));
		}

		private static PrivateKey toEcPrivateKey(String curve, String hex)
		{
			try
			{
				AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
				params.init(new ECGenParameterSpec(curve));
				ECParameterSpec ecParams = params.getParameterSpec(ECParameterSpec.class);
				ECPrivateKeySpec spec = new ECPrivateKeySpec(new BigInteger(1, HexFormat.of().parseHex(hex)), ecParams);
				return KeyFactory.getInstance("EC").generatePrivate(spec);
			}
			catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidParameterSpecException e)
			{
				throw new RuntimeException(e);
			}
		}

		@Override
		public final String toString()
		{
			return name;
		}
	}

	// Test Data from https://www.rfc-editor.org/rfc/rfc9180.html#name-test-vectors

	private static final byte[] INFO = HexFormat.of().parseHex("4f6465206f6e2061204772656369616e2055726e");

	private static final byte[] PSK_ID = HexFormat.of().parseHex("456e6e796e20447572696e206172616e204d6f726961");
	private static final SecretKey PSK = new SecretKeySpec(
			HexFormat.of().parseHex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"), "Generic");

	private static final Rfc9180TestData A11 = Rfc9180TestData.withX25519("A.1.1", Mode.base(),
			KemId.DHKEM_X25519_HKDF_SHA256, KdfId.HKDF_SHA256, AeadId.AES_128_GCM,
			"4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
			"37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
			"fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc", //
			"4531685d41d65f03dc48f6b8302c05b0", "56d890e5accaaf011cff4b7d");
	private static final Rfc9180TestData A12 = Rfc9180TestData.withX25519("A.1.2", Mode.psk(PSK_ID, PSK),
			KemId.DHKEM_X25519_HKDF_SHA256, KdfId.HKDF_SHA256, AeadId.AES_128_GCM,
			"c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd",
			"0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b",
			"727699f009ffe3c076315019c69648366b69171439bd7dd0807743bde76986cd", //
			"15026dba546e3ae05836fc7de5a7bb26", "9518635eba129d5ce0914555");

	private static final Rfc9180TestData A21 = Rfc9180TestData.withX25519("A.2.1", Mode.base(),
			KemId.DHKEM_X25519_HKDF_SHA256, KdfId.HKDF_SHA256, AeadId.ChaCha20Poly1305,
			"8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
			"1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
			"0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
			"ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91", "5c4d98150661b848853b547f");
	private static final Rfc9180TestData A22 = Rfc9180TestData.withX25519("A.2.2", Mode.psk(PSK_ID, PSK),
			KemId.DHKEM_X25519_HKDF_SHA256, KdfId.HKDF_SHA256, AeadId.ChaCha20Poly1305,
			"77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879",
			"2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04",
			"4be079c5e77779d0215b3f689595d59e3e9b0455d55662d1f3666ec606e50ea7",
			"600d2fdb0313a7e5c86a9ce9221cd95bed069862421744cfb4ab9d7203a9c019", "112e0465562045b7368653e7");

	private static final Rfc9180TestData A31 = Rfc9180TestData.withSecp256r1("A.3.1", Mode.base(),
			KemId.DHKEM_P256_HKDF_SHA256, KdfId.HKDF_SHA256, AeadId.AES_128_GCM,
			"f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
			"04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325"
					+ "ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
			"c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8", //
			"868c066ef58aae6dc589b6cfdd18f97e", "4e0bc5018beba4bf004cca59");
	private static final Rfc9180TestData A32 = Rfc9180TestData.withSecp256r1("A.3.2", Mode.psk(PSK_ID, PSK),
			KemId.DHKEM_P256_HKDF_SHA256, KdfId.HKDF_SHA256, AeadId.AES_128_GCM,
			"438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661",
			"04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e"
					+ "4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f",
			"2e783ad86a1beae03b5749e0f3f5e9bb19cb7eb382f2fb2dd64c99f15ae0661b", //
			"55d9eb9d26911d4c514a990fa8d57048", "b595dc6b2d7e2ed23af529b1");

	private static final Rfc9180TestData A41 = Rfc9180TestData.withSecp256r1("A.4.1", Mode.base(),
			KemId.DHKEM_P256_HKDF_SHA256, KdfId.HKDF_SHA512, AeadId.AES_128_GCM,
			"3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38",
			"0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a1"
					+ "5565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580",
			"02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd", //
			"090ca96e5f8aa02b69fac360da50ddf9", "9c995e621bf9a20c5ca45546");
	private static final Rfc9180TestData A42 = Rfc9180TestData.withSecp256r1("A.4.2", Mode.psk(PSK_ID, PSK),
			KemId.DHKEM_P256_HKDF_SHA256, KdfId.HKDF_SHA512, AeadId.AES_128_GCM,
			"bc6f0b5e22429e5ff47d5969003f3cae0f4fec50e23602e880038364f33b8522",
			"04a307934180ad5287f95525fe5bc6244285d7273c15e061f0f2efb211c3505"
					+ "7f3079f6e0abae200992610b25f48b63aacfcb669106ddee8aa023feed301901371",
			"2912aacc6eaebd71ff715ea50f6ef3a6637856b2a4c58ea61e0c3fc159e3bc16", //
			"0b910ba8d9cfa17e5f50c211cb32839a", "0c29e714eb52de5b7415a1b7");

	private static final Rfc9180TestData A51 = Rfc9180TestData.withSecp256r1("A.5.1", Mode.base(),
			KemId.DHKEM_P256_HKDF_SHA256, KdfId.HKDF_SHA256, AeadId.ChaCha20Poly1305,
			"a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b",
			"04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824"
					+ "fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291",
			"806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850",
			"a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc", "726b4390ed2209809f58c693");
	private static final Rfc9180TestData A52 = Rfc9180TestData.withSecp256r1("A.5.2", Mode.psk(PSK_ID, PSK),
			KemId.DHKEM_P256_HKDF_SHA256, KdfId.HKDF_SHA256, AeadId.ChaCha20Poly1305,
			"12ecde2c8bc2d5d7ed2219c71f27e3943d92b344174436af833337c557c300b3",
			"04f336578b72ad7932fe867cc4d2d44a718a318037a0ec271163699cee653fa"
					+ "805c1fec955e562663e0c2061bb96a87d78892bff0cc0bad7906c2d998ebe1a7246",
			"ac4f260dce4db6bf45435d9c92c0e11cfdd93743bd3075949975974cc2b3d79e",
			"6d61cb330b7771168c8619498e753f16198aad9566d1f1c6c70e2bc1a1a8b142", "0de7655fb65e1cd51a38864e");

	private static final Rfc9180TestData A61 = Rfc9180TestData.withSecp521r1("A.6.1", Mode.base(),
			KemId.DHKEM_P521_HKDF_SHA512, KdfId.HKDF_SHA512, AeadId.AES_256_GCM,
			"01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c2"
					+ "7196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b24628" //
					+ "47",
			"040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab89"
					+ "00aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731e"
					+ "ce2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed06"
					+ "92237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0",
			"776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1"
					+ "d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46" //
					+ "d30e818",
			"751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70", "55ff7a7d739c69f44b25447b");
	private static final Rfc9180TestData A62 = Rfc9180TestData.withSecp521r1("A.6.2", Mode.psk(PSK_ID, PSK),
			KemId.DHKEM_P521_HKDF_SHA512, KdfId.HKDF_SHA512, AeadId.AES_256_GCM,
			"011bafd9c7a52e3e71afbdab0d2f31b03d998a0dc875dd7555c63560e142bd"
					+ "e264428de03379863b4ec6138f813fa009927dc5d15f62314c56d4e7ff2b485753eb" //
					+ "72",
			"040085eff0835cc84351f32471d32aa453cdc1f6418eaaecf1c2824210eb1d4"
					+ "8d0768b368110fab21407c324b8bb4bec63f042cfa4d0868d19b760eb4beba1bff79"
					+ "3b30036d2c614d55730bd2a40c718f9466faf4d5f8170d22b6df98dfe0c067d02b34"
					+ "9ae4a142e0c03418f0a1479ff78a3db07ae2c2e89e5840f712c174ba2118e90fdcb",
			"0d52de997fdaa4797720e8b1bebd3df3d03c4cf38cc8c1398168d"
					+ "36c3fc7626428c9c254dd3f9274450909c64a5b3acbe45e2d850a2fd69ac0605fe5c" //
					+ "8a057a5",
			"f764a5a4b17e5d1ffba6e699d65560497ebaea6eb0b0d9010a6d979e298a39ff", "479afdf3546ddba3a9841f38");

	private static Stream<Arguments> forTestExecuteKeySchedule()
	{
		return Stream.of(Arguments.of(A11), Arguments.of(A12), Arguments.of(A21), Arguments.of(A22), Arguments.of(A31),
				Arguments.of(A32), Arguments.of(A41), Arguments.of(A42), Arguments.of(A51), Arguments.of(A52),
				Arguments.of(A61), Arguments.of(A62));
	}

	@ParameterizedTest
	@MethodSource("forTestExecuteKeySchedule")
	void testExecuteKeySchedule(Rfc9180TestData testData) throws Exception
	{
		KemWrapper kem = testData.kemId().toKem();
		assertNotNull(kem);

		SecretKey sharedSecret = kem.getSharedSecret(testData.skRm(), testData.enc());
		assertNotNull(sharedSecret);
		assertArrayEquals(testData.sharedSecret(), sharedSecret.getEncoded());

		KeySchedule keySchedule = new KeySchedule(testData.mode(), testData.kemId(), testData.kdfId(),
				testData.aeadId(), INFO);

		Result result = keySchedule.executeKeySchedule(sharedSecret);
		assertNotNull(result);

		assertNotNull(result.key());
		assertNotNull(result.baseNonce());

		assertArrayEquals(testData.key(), result.key().getEncoded());
		assertArrayEquals(testData.baseNonce(), result.baseNonce());
	}
}

package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;

public class HpkeDemo
{
	private static final int GIB_1 = 1024 * 1024 * 1024;

	@Test
	void v1WriteReadBaseModeDemo() throws Exception
	{
		byte[] receiverKeyId = new byte[ProtocolV1.RECEIVER_KEY_ID_LENGTH];
		KemId kemId = KemId.DHKEM_X25519_HKDF_SHA256;
		KeyPair keyPair = kemId.getKeyPairGeneratorFactory().initialize().generateKeyPair();
		PreSharedKeyProvider preSharedKeyProvider = PreSharedKeyProvider.of();
		ReceiverPrivateKeyProvider receiverPrivateKeyProvider = ReceiverPrivateKeyProvider.of(receiverKeyId,
				keyPair.getPrivate());
		ProtocolV1 protocol = new ProtocolV1(Mode.base(), kemId, KdfId.HKDF_SHA256, AeadId.AES_128_GCM,
				ChunkLength.MiB_1, receiverKeyId);
		ProtocolFactory protocolFactory = new ProtocolFactory(preSharedKeyProvider, receiverPrivateKeyProvider);
		Hpke hpke = new Hpke(protocolFactory);

		InputStream encrypted = hpke.encrypt(protocol, new ZeroInputStream(GIB_1), keyPair.getPublic());
		hpke.decrypt(encrypted, OutputStream.nullOutputStream());
	}
}

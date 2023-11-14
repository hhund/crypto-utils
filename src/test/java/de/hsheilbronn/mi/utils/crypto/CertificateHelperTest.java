package de.hsheilbronn.mi.utils.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.Test;

public class CertificateHelperTest
{
	@Test
	public void testCreateRsaKeyPair() throws Exception
	{
		KeyPair pair = CertificateHelper.createRsaKeyPair4096Bit();
		assertNotNull(pair);
		assertNotNull(pair.getPrivate());
		assertNotNull(pair.getPublic());
		assertTrue(pair.getPublic() instanceof RSAPublicKey);
		assertTrue(pair.getPrivate() instanceof RSAPrivateKey);
	}
}

package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.EnumSet;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;

public class DhKemWrapper extends AbstractKemWrapper implements KemWrapper
{
	public static final EnumSet<KemId> DH_KEMS = EnumSet.of(KemId.DHKEM_P256_HKDF_SHA256, KemId.DHKEM_P384_HKDF_SHA384,
			KemId.DHKEM_P521_HKDF_SHA512, KemId.DHKEM_X25519_HKDF_SHA256, KemId.DHKEM_X448_HKDF_SHA512);

	public DhKemWrapper(KemId kemId)
	{
		super(kemId);

		if (!DH_KEMS.contains(kemId))
			throw new IllegalArgumentException("KemId " + kemId.name() + " not supported");
	}

	@Override
	protected Encapsulated doGetEncapsulated(PublicKey publicKey, SecureRandom secureRandom, int sharedSecretLength)
			throws NoSuchAlgorithmException, InvalidKeyException
	{
		return createKem().newEncapsulator(publicKey, secureRandom).encapsulate();
	}

	@Override
	protected SecretKey doGetSecretKey(PrivateKey privateKey, byte[] encapsulation, int sharedSecretLength)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException
	{
		return createKem().newDecapsulator(privateKey).decapsulate(encapsulation);
	}

	private KEM createKem() throws NoSuchAlgorithmException
	{
		return KEM.getInstance("DHKEM");
	}
}

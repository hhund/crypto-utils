package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;

public class DhKemWrapper extends AbstractKemWrapper implements KemWrapper
{
	public DhKemWrapper(KemId kemId)
	{
		super(kemId);
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

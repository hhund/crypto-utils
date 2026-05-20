package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;

public abstract class AbstractKemWrapper implements KemWrapper
{
	private final KemId kemId;

	public AbstractKemWrapper(KemId kemId)
	{
		this.kemId = Objects.requireNonNull(kemId, "kemId");
	}

	@Override
	public final Encapsulated getEncapsulated(PublicKey publicKey, SecureRandom secureRandom)
			throws NoSuchAlgorithmException, InvalidKeyException
	{
		if (!kemId.isKeySupported(publicKey))
			throw new IllegalArgumentException("publicKey not supported");

		Encapsulated encapsulated = doGetEncapsulated(publicKey, secureRandom, kemId.getSharedSecretLength());

		if (encapsulated.encapsulation().length != kemId.getEncapsulationLength())
			throw new IllegalStateException("encapsulation.length not " + kemId.getEncapsulationLength());

		return encapsulated;
	}

	protected abstract Encapsulated doGetEncapsulated(PublicKey publicKey, SecureRandom secureRandom,
			int sharedSecretLength) throws NoSuchAlgorithmException, InvalidKeyException;


	@Override
	public final SecretKey getSharedSecret(PrivateKey privateKey, byte[] encapsulation)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException
	{
		if (!kemId.isKeySupported(privateKey))
			throw new IllegalArgumentException("privateKey not supported");

		if (encapsulation.length != kemId.getEncapsulationLength())
			throw new DecapsulateException("encapsulation.length not " + kemId.getEncapsulationLength());

		SecretKey sharedSecret = doGetSecretKey(privateKey, encapsulation, kemId.getSharedSecretLength());

		if (sharedSecret.getEncoded().length != kemId.getSharedSecretLength())
			throw new IllegalStateException("sharedSecret.length not " + kemId.getSharedSecretLength());

		return sharedSecret;
	}

	protected abstract SecretKey doGetSecretKey(PrivateKey privateKey, byte[] encapsulation, int sharedSecretLength)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException;
}

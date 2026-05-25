package de.hsheilbronn.mi.utils.crypto.hpke;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.SecretKey;

public interface KemWrapper
{
	Encapsulated getEncapsulated(PublicKey publicKey, SecureRandom secureRandom)
			throws NoSuchAlgorithmException, InvalidKeyException, KeyNotSupportedException;

	SecretKey getSharedSecret(PrivateKey privateKey, byte[] encapsulation)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException, KeyNotSupportedException;
}

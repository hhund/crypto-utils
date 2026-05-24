package de.hsheilbronn.mi.utils.crypto.hpke;

public interface Protocol
{
	Mode getMode();

	KemId getKemId();

	KdfId getKdfId();

	AeadId getAeadId();

	int getChunkLength();

	byte[] getReceiverKeyId();

	byte[] getKdfInfo();
}

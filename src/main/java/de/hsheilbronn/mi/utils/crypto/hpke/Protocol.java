package de.hsheilbronn.mi.utils.crypto.hpke;

public interface Protocol
{
	Mode getMode();

	KemId getKemId();

	KdfId getKdfId();

	AeadId getAeadId();

	ChunkLength getChunkLength();

	byte[] getReceiverKeyId();

	byte[] getKdfInfo();
}

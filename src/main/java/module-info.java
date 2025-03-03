module de.hsheilbronn.mi.utils.crypto
{
	requires transitive org.bouncycastle.pkix;
	requires transitive org.bouncycastle.provider;
	requires org.slf4j;

	exports de.hsheilbronn.mi.utils.crypto.ca;
	exports de.hsheilbronn.mi.utils.crypto.check;
	exports de.hsheilbronn.mi.utils.crypto.context;
	exports de.hsheilbronn.mi.utils.crypto.io;
	exports de.hsheilbronn.mi.utils.crypto.kem;
	exports de.hsheilbronn.mi.utils.crypto.keypair;
	exports de.hsheilbronn.mi.utils.crypto.keystore;
}
package de.hsheilbronn.mi.utils.crypto.ca;

import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class JcaContentSignerBuilderFactory
{
	private JcaContentSignerBuilderFactory()
	{
	}

	public static JcaContentSignerBuilder algorithm(String signatureAlgorith)
	{
		return new JcaContentSignerBuilder(signatureAlgorith);
	}

	public static JcaContentSignerBuilder sha256WithRsa()
	{
		return new JcaContentSignerBuilder("SHA256WithRSA");
	}

	public static JcaContentSignerBuilder sha512WithRsa()
	{
		return new JcaContentSignerBuilder("SHA512WithRSA");
	}

	public static JcaContentSignerBuilder sha256withEcdsa()
	{
		return new JcaContentSignerBuilder("SHA256withECDSA");
	}

	public static JcaContentSignerBuilder sha384withEcdsa()
	{
		return new JcaContentSignerBuilder("SHA384withECDSA");
	}

	public static JcaContentSignerBuilder sha512withEcdsa()
	{
		return new JcaContentSignerBuilder("SHA512withECDSA");
	}

	public static JcaContentSignerBuilder ed25519()
	{
		return new JcaContentSignerBuilder("Ed25519");
	}

	public static JcaContentSignerBuilder ed448()
	{
		return new JcaContentSignerBuilder("Ed448");
	}
}

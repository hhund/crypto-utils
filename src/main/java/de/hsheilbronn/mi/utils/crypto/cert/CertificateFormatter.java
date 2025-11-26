package de.hsheilbronn.mi.utils.crypto.cert;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

public class CertificateFormatter
{
	private CertificateFormatter()
	{
	}

	public static enum X500PrincipalFormat
	{
		RFC1779, RFC2253, CANONICAL
	}

	/**
	 * @param format
	 *            not <code>null</code>
	 * @return {@link Function} to extract the subject name from a {@link X509Certificate}
	 */
	public static Function<X509Certificate, String> toSubjectName(X500PrincipalFormat format)
	{
		Objects.requireNonNull(format, "format");

		return certificate -> toSubjectName(certificate, format);
	}

	/**
	 * @param certificate
	 *            not <code>null</code>
	 * @param format
	 *            not <code>null</code>
	 * @return certificate subject name with the given <b>format</b>
	 */
	public static String toSubjectName(X509Certificate certificate, X500PrincipalFormat format)
	{
		Objects.requireNonNull(certificate, "certificate");
		Objects.requireNonNull(format, "format");

		return certificate.getSubjectX500Principal().getName(format.name());
	}

	/**
	 * @return multi-line text with values from given <b>Certificate</b> formatted similar to the output of
	 *         <code>openssl x509 -text -noout</code>
	 */
	public static Function<X509Certificate, String> toOpenSslStyleText()
	{
		return certificate -> toOpenSslStyleText(certificate);
	}

	/**
	 * @param certificate
	 *            not <code>null</code>
	 * @return multi-line text with values from given <b>Certificate</b> formatted similar to the output of
	 *         <code>openssl x509 -text -noout</code>
	 */
	public static String toOpenSslStyleText(X509Certificate certificate)
	{
		Objects.requireNonNull(certificate, "cert");

		try
		{
			final JcaX509CertificateHolder holder = new JcaX509CertificateHolder(certificate);

			StringBuilder b = new StringBuilder();
			b.append("Certificate:\n    Data:\n        Version: ");
			b.append(certificate.getVersion());
			b.append(" (0x");
			b.append((certificate.getVersion() - 1));
			b.append(")\n        Serial Number:\n            ");
			b.append(HexFormat.ofDelimiter(":").formatHex(certificate.getSerialNumber().toByteArray()));
			b.append("\n        Signature Algorithm: ");
			b.append(certificate.getSigAlgName());
			b.append("\n        Issuer: ");
			b.append(certificate.getIssuerX500Principal().getName(X500PrincipalFormat.RFC1779.name()));
			b.append("\n        Validity\n            Not Before: ");
			b.append(certificate.getNotBefore());
			b.append("\n            Not After : ");
			b.append(certificate.getNotAfter());
			b.append("\n        Subject: ");
			b.append(certificate.getSubjectX500Principal().getName(X500PrincipalFormat.RFC1779.name()));
			b.append("\n        Subject Public Key Info:\n            Public Key Algorithm: ");
			b.append(certificate.getPublicKey().getAlgorithm());
			b.append('\n');
			appendSubjectPublicKeyInfo(b, "            ", holder.getSubjectPublicKeyInfo(), certificate.getPublicKey());
			b.append("\n        X509v3 extensions:\n");
			appendSubjectKeyIdentifier(b, "            ", holder);
			appendBasicConstraint(b, "            ", holder);
			appendKeyUsage(b, "            ", holder, certificate);
			appendExtendedKeyUsage(b, "            ", holder);
			appendSubjectAlternativeName(b, "            ", holder);
			appendAuthorityKeyIdentifier(b, "            ", holder);
			appendDistributionPointFullNames(b, "            ", holder);
			b.append("    Signature Algorithm: ");
			b.append(certificate.getSigAlgName());
			b.append('\n');
			toLines(b, "        ", HexFormat.ofDelimiter(":").formatHex((certificate.getSignature())), 54);

			return b.toString();
		}
		catch (CertificateEncodingException e)
		{
			throw new RuntimeException(e);
		}
	}

	private static void appendSubjectPublicKeyInfo(StringBuilder b, String prefix,
			SubjectPublicKeyInfo subjectPublicKeyInfo, PublicKey publicKey)
	{
		if (publicKey instanceof RSAPublicKey rsa)
			getSubjectPublicKeyInfoRsa(b, prefix, rsa);
		else if (publicKey instanceof ECPublicKey)
			getSubjectPublicKeyInfoEc(b, prefix, subjectPublicKeyInfo);
		else if (publicKey instanceof EdECPublicKey ed)
			getSubjectPublicKeyInfoEd(b, prefix, subjectPublicKeyInfo, ed);
	}

	private static void getSubjectPublicKeyInfoRsa(StringBuilder b, String prefix, RSAPublicKey rsaPublicKey)
	{
		b.append(prefix);
		b.append("    Public-Key: (");
		b.append(rsaPublicKey.getModulus().bitLength());
		b.append(" bit)");
		b.append('\n');

		b.append(prefix);
		b.append("    Modulus:");
		b.append('\n');

		toLines(b, prefix + "        ", HexFormat.ofDelimiter(":").formatHex(rsaPublicKey.getModulus().toByteArray()),
				45);
		b.append('\n');
		b.append(prefix);
		b.append("    Exponent: " + rsaPublicKey.getPublicExponent());
	}

	private static void getSubjectPublicKeyInfoEc(StringBuilder b, String prefix,
			SubjectPublicKeyInfo subjectPublicKeyInfo)
	{
		int keyLength = getKeyLength(subjectPublicKeyInfo.getAlgorithm().getParameters());
		if (keyLength > 0)
		{
			b.append(prefix);
			b.append("    Public-Key: (");
			b.append(keyLength);
			b.append(" bit)");
			b.append('\n');
		}

		b.append(prefix);
		b.append("    pub:");
		b.append('\n');
		toLines(b, prefix + "        ",
				HexFormat.ofDelimiter(":").formatHex(subjectPublicKeyInfo.getPublicKeyData().getBytes()), 45);

		String asn1Oid = getAsn1Oid(subjectPublicKeyInfo.getAlgorithm().getParameters());
		if (asn1Oid != null)
		{
			b.append('\n');
			b.append(prefix);
			b.append("    ASN1 OID: ");
			b.append(asn1Oid);
		}

		String nistCurve = getNistCurve(subjectPublicKeyInfo.getAlgorithm().getParameters());
		if (nistCurve != null)
		{
			b.append('\n');
			b.append(prefix);
			b.append("    NIST CURVE: ");
			b.append(nistCurve);
		}
	}

	private static void getSubjectPublicKeyInfoEd(StringBuilder b, String prefix,
			SubjectPublicKeyInfo subjectPublicKeyInfo, EdECPublicKey ed)
	{
		b.append(prefix);
		b.append("    ");
		b.append(ed.getParams().getName());
		b.append(" Public-Key: ");
		b.append('\n');

		b.append(prefix);
		b.append("    pub:");
		b.append('\n');
		toLines(b, prefix + "        ",
				HexFormat.ofDelimiter(":").formatHex(subjectPublicKeyInfo.getPublicKeyData().getBytes()), 45);
	}

	private static String getAsn1Oid(ASN1Encodable encodable)
	{
		if (SECObjectIdentifiers.secp256r1.equals(encodable))
			return "P-256";
		if (SECObjectIdentifiers.secp384r1.equals(encodable))
			return "P-384";
		if (SECObjectIdentifiers.secp521r1.equals(encodable))
			return "P-521";
		else
			return null;
	}

	private static String getNistCurve(ASN1Encodable encodable)
	{
		if (SECObjectIdentifiers.secp256r1.equals(encodable))
			return "secp256r1";
		if (SECObjectIdentifiers.secp384r1.equals(encodable))
			return "secp384r1";
		if (SECObjectIdentifiers.secp521r1.equals(encodable))
			return "secp521r1";
		else
			return null;
	}

	private static int getKeyLength(ASN1Encodable encodable)
	{
		if (SECObjectIdentifiers.secp256r1.equals(encodable))
			return 256;
		if (SECObjectIdentifiers.secp384r1.equals(encodable))
			return 384;
		if (SECObjectIdentifiers.secp521r1.equals(encodable))
			return 521;
		else
			return Integer.MIN_VALUE;
	}

	private static void appendSubjectKeyIdentifier(StringBuilder b, String prefix, JcaX509CertificateHolder holder)
	{
		Extension skie = holder.getExtensions().getExtension(Extension.subjectKeyIdentifier);
		if (skie != null)
		{
			b.append(prefix);
			b.append("X509v3 Subject Key Identifier:\n");
			SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(skie.getExtnValue());
			b.append(prefix);
			b.append("    ");
			b.append(HexFormat.ofDelimiter(":").formatHex(ski.getKeyIdentifier()));
			b.append('\n');
		}
	}

	private static void appendBasicConstraint(StringBuilder b, String prefix, JcaX509CertificateHolder holder)
	{
		BasicConstraints bc = BasicConstraints.fromExtensions(holder.getExtensions());
		if (bc != null)
		{
			b.append(prefix);
			b.append("X509v3 Basic Constraints:");
			appendCritical(b, holder, Extension.basicConstraints);
			b.append('\n');
			b.append(prefix);
			b.append("    CA:");
			b.append(bc.isCA());

			BigInteger pathLength = bc.getPathLenConstraint();
			if (pathLength != null)
			{
				b.append(", pathlen:");
				b.append(pathLength);
			}

			b.append('\n');
		}
	}

	private static void appendCritical(StringBuilder b, JcaX509CertificateHolder holder,
			ASN1ObjectIdentifier extensionId)
	{
		if (holder.getExtension(extensionId).isCritical())
			b.append(" critical");
	}

	private static void toLines(StringBuilder b, String prefix, String value, int length)
	{
		for (int i = 0; i < value.length(); i += length)
		{
			b.append(prefix);
			b.append(value.substring(i, (i + length) > value.length() ? value.length() : i + length));

			if ((i + length) < value.length())
				b.append('\n');
		}
	}

	private static void appendKeyUsage(StringBuilder b, String prefix, JcaX509CertificateHolder holder,
			X509Certificate cert)
	{
		boolean[] ku = cert.getKeyUsage();
		if (ku == null)
			return;

		List<String> keyUsages = new ArrayList<>();
		if (ku[0])
			keyUsages.add("Digital Signature");
		if (ku[1])
			keyUsages.add("Non Repudiation");
		if (ku[2])
			keyUsages.add("Key Encipherment");
		if (ku[3])
			keyUsages.add("Data Encipherment");
		if (ku[4])
			keyUsages.add("Key Agreement");
		if (ku[5])
			keyUsages.add("Key Cert Sign");
		if (ku[6])
			keyUsages.add("CRL Sign");
		if (ku[7])
			keyUsages.add("Encipher Only");
		if (ku[8])
			keyUsages.add("Decipher Only");

		b.append(prefix);
		b.append("X509v3 Key Usage:");
		appendCritical(b, holder, Extension.keyUsage);
		b.append('\n');
		if (!keyUsages.isEmpty())
		{
			b.append(prefix);
			b.append("    ");
			b.append(keyUsages.stream().collect(Collectors.joining(", ")));
			b.append('\n');
		}
	}

	private static void appendExtendedKeyUsage(StringBuilder b, String prefix, JcaX509CertificateHolder holder)
	{
		ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(holder.getExtensions());
		if (eku == null)
			return;

		List<String> extendedKeyUsages = new ArrayList<>();
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth))
			extendedKeyUsages.add("TLS Web Server Authentication");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth))
			extendedKeyUsages.add("TLS Web Client Authentication");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning))
			extendedKeyUsages.add("Code Signing");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection))
			extendedKeyUsages.add("Email Protection");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecEndSystem))
			extendedKeyUsages.add("IPsec End System");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecTunnel))
			extendedKeyUsages.add("IPsec Tunnel");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecUser))
			extendedKeyUsages.add("IPsec User");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping))
			extendedKeyUsages.add("Time Stamping");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning))
			extendedKeyUsages.add("OCSP Signing");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_dvcs))
			extendedKeyUsages.add("DVCS");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_sbgpCertAAServerAuth))
			extendedKeyUsages.add("SBGP CERT AA SERVER AUTH");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_scvp_responder))
			extendedKeyUsages.add("SCVP RESPONDER");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_eapOverPPP))
			extendedKeyUsages.add("EAP OVER PPP");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_eapOverLAN))
			extendedKeyUsages.add("EAP OVER LAN");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_scvpServer))
			extendedKeyUsages.add("SCVP SERVER");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_scvpClient))
			extendedKeyUsages.add("SCVP CLIENT");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecIKE))
			extendedKeyUsages.add("IPSEC IKE");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_capwapAC))
			extendedKeyUsages.add("CAPWAP AC");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_capwapWTP))
			extendedKeyUsages.add("CAPWAP WTP");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_cmcCA))
			extendedKeyUsages.add("CMC CA");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_cmcRA))
			extendedKeyUsages.add("CMC RA");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_cmKGA))
			extendedKeyUsages.add("CM KGA");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_smartcardlogon))
			extendedKeyUsages.add("SMARTCARD LOGON");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_macAddress))
			extendedKeyUsages.add("MAC ADDRESS");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_msSGC))
			extendedKeyUsages.add("MS SGC");
		if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_nsSGC))
			extendedKeyUsages.add("NS SGC");

		b.append(prefix);
		b.append("X509v3 Extended Key Usage:");
		appendCritical(b, holder, Extension.extendedKeyUsage);
		b.append('\n');

		if (!extendedKeyUsages.isEmpty())
		{
			b.append(prefix);
			b.append("    ");
			b.append(extendedKeyUsages.stream().collect(Collectors.joining(", ")));
			b.append('\n');
		}
	}

	private static void appendSubjectAlternativeName(StringBuilder b, String prefix, JcaX509CertificateHolder holder)
	{
		GeneralNames san = GeneralNames.fromExtensions(holder.getExtensions(), Extension.subjectAlternativeName);
		if (san == null)
			return;

		List<String> subjectAlternativeNames = Arrays.stream(san.getNames())
				.map(n -> toGeneralNameLabel(n.getTagNo()) + ":" + n.getName().toString()).toList();

		b.append(prefix);
		b.append("X509v3 Subject Alternative Name:");
		appendCritical(b, holder, Extension.subjectAlternativeName);
		b.append('\n');

		if (!subjectAlternativeNames.isEmpty())
		{
			b.append(prefix);
			b.append("    ");
			b.append(subjectAlternativeNames.stream().collect(Collectors.joining(", ")));
			b.append('\n');
		}
	}

	private static String toGeneralNameLabel(int generalNameTag)
	{
		return switch (generalNameTag)
		{
			case GeneralName.otherName -> "Other";
			case GeneralName.rfc822Name -> "Email";
			case GeneralName.dNSName -> "DNS";
			case GeneralName.x400Address -> "X400Address";
			case GeneralName.directoryName -> "Directory";
			case GeneralName.ediPartyName -> "EdiPartyName";
			case GeneralName.uniformResourceIdentifier -> "URI";
			case GeneralName.iPAddress -> "IP";
			case GeneralName.registeredID -> "Registered Identifier";
			default -> throw new IllegalArgumentException("Unexpected value: " + generalNameTag);
		};
	}

	private static void appendAuthorityKeyIdentifier(StringBuilder b, String prefix, JcaX509CertificateHolder holder)
	{
		b.append(prefix);
		b.append("X509v3 Authority Key Identifier:\n");

		AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(holder.getExtensions());
		if (aki != null)
		{
			b.append(prefix);
			b.append("    ");
			b.append(HexFormat.ofDelimiter(":").formatHex(aki.getKeyIdentifierOctets()));
			b.append('\n');
		}
	}

	private static void appendDistributionPointFullNames(StringBuilder b, String prefix,
			JcaX509CertificateHolder holder)
	{
		CRLDistPoint cdp = CRLDistPoint.fromExtensions(holder.getExtensions());
		if (cdp == null)
			return;

		b.append(prefix);
		b.append("X509v3 CRL Distribution Points:\n");
		b.append(prefix);
		b.append("    Full Name:\n");

		String crlDistributionPoints = Arrays.stream(cdp.getDistributionPoints())
				.map(DistributionPoint::getDistributionPoint)
				.filter(p -> DistributionPointName.FULL_NAME == p.getType()).map(DistributionPointName::getName)
				.filter(n -> n instanceof GeneralNames).map(n -> (GeneralNames) n)
				.flatMap(n -> Arrays.stream(n.getNames()))
				.map(n -> toGeneralNameLabel(n.getTagNo()) + ":" + n.getName().toString())
				.collect(Collectors.joining(", "));

		if (!crlDistributionPoints.isEmpty())
		{
			b.append(prefix);
			b.append("        ");
			b.append(crlDistributionPoints);
			b.append('\n');
		}
	}
}

package de.rwh.utils.crypto.io;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.apache.commons.codec.binary.Base64;

public abstract class AbstractCertIo
{
	protected static void writeEncoded(byte[] encoded, Path file, String firstLine, String lastLine, Charset charset,
			int lineLength) throws IOException
	{
		try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(file)))
		{
			writeEncoded(encoded, firstLine, lastLine, charset, lineLength, out);
		}
	}

	protected static String writeEncoded(byte[] encoded, String firstLine, String lastLine, Charset charset,
			int lineLength) throws IOException
	{
		try (ByteArrayOutputStream out = new ByteArrayOutputStream())
		{
			return new String(writeEncoded(encoded, firstLine, lastLine, charset, lineLength, out).toByteArray(),
					charset);
		}
	}

	private static <O extends OutputStream> O writeEncoded(byte[] encoded, String firstLine, String lastLine,
			Charset charset, int lineLength, O out) throws IOException
	{
		byte[] base64Encoded = Base64.encodeBase64(encoded);

		out.write(firstLine.getBytes(charset));
		out.write('\n');

		for (int s = 0; s < base64Encoded.length; s += lineLength)
		{
			out.write(base64Encoded, s, Math.min(lineLength, base64Encoded.length - s));
			out.write('\n');
		}

		out.write(lastLine.getBytes(charset));
		out.write('\n');

		return out;
	}

	protected static byte[] readEncoded(Path file, String firstLine, String lastLine, Charset charset, int lineLength)
			throws IOException
	{
		String base64Encoded = readBase64Encoded(file, firstLine, lastLine, charset, lineLength);
		return Base64.decodeBase64(base64Encoded);
	}

	protected static byte[] readEncoded(String content, String firstLine, String lastLine)
			throws IOException
	{
		String base64Encoded = readBase64Encoded(content, firstLine, lastLine);
		return Base64.decodeBase64(base64Encoded);
	}

	protected static String readBase64Encoded(Path file, String firstLine, String lastLine, Charset charset,
			int lineLength) throws IOException
	{
		List<String> lines = Files.readAllLines(file, charset);
		if (lines.size() < 3)
			throw new IOException("File too short");

		if (!lines.get(0).equals(firstLine))
			throw new IOException("First line must be: " + firstLine + "\\n");
		else
			lines.remove(0);
		if (!lines.get(lines.size() - 1).equals(lastLine))
			throw new IOException("Last line must be: " + lastLine + "\\n");
		else
			lines.remove(lines.size() - 1);

		StringBuilder base64Encoded = new StringBuilder();
		for (int i = 0; i < lines.size(); i++)
		{
			String l = lines.get(i);
			if (l.length() > lineLength)
				throw new IOException(
						String.format(
								"Base64 encoded value lines must be not longer than %d characters (\\n exclusive), line %d: %d characters.",
								lineLength, i + 1, l.length()));
			else
				base64Encoded.append(l);
		}

		return base64Encoded.toString();
	}

	protected static String readBase64Encoded(String content, String firstLine, String lastLine) throws IOException
	{
		if (content == null || content.isEmpty())
			throw new IOException("content null or empty");
		if (!content.startsWith(firstLine))
			throw new IOException("content must start with " + firstLine);
		if (!content.endsWith(lastLine))
			throw new IOException("content must end with " + firstLine);
		if (content.matches("\\s"))
			throw new IOException("content contains whitespace (java regex \\s)");

		return content.substring(firstLine.length(), content.length() - lastLine.length()).replaceAll("\\s", "");
	}
}

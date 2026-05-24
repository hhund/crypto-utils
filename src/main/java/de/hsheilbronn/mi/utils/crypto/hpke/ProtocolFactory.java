package de.hsheilbronn.mi.utils.crypto.hpke;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class ProtocolFactory
{
	public static final byte[] MAGIC = new byte[] { 'H', 'P', 'K', 'E', 'F' };

	public static final int ROOT_HEADER_LENGTH = MAGIC.length + 1;

	public static interface ProtocolSerializer<P extends Protocol>
	{
		int getVersion();

		P read(InputStream source, PreSharedKeyProvider preSharedKeyProvider,
				ReceiverPrivateKeyProvider receiverKeyProvider) throws IOException;

		Class<P> getType();

		byte[] write(P protocol);
	}

	public static final ProtocolSerializer<ProtocolV1> V1_SERIALIZER = new ProtocolSerializer<ProtocolV1>()
	{
		@Override
		public int getVersion()
		{
			return ProtocolV1.VERSION;
		}

		@Override
		public ProtocolV1 read(InputStream source, PreSharedKeyProvider preSharedKeyProvider,
				ReceiverPrivateKeyProvider receiverKeyProvider) throws IOException
		{
			return ProtocolV1.from(source, preSharedKeyProvider, receiverKeyProvider);
		}

		@Override
		public Class<ProtocolV1> getType()
		{
			return ProtocolV1.class;
		}

		@Override
		public byte[] write(ProtocolV1 protocol)
		{
			return protocol.getCanonicalHeader();
		}
	};

	private final PreSharedKeyProvider preSharedKeyProvider;
	private final ReceiverPrivateKeyProvider receiverPrivateKeyProvider;

	private final List<ProtocolSerializer<? extends Protocol>> protocolSerializers = new ArrayList<>();

	/**
	 * @param preSharedKeyProvider
	 *            not <code>null</code>
	 * @param receiverPrivateKeyProvider
	 *            not <code>null</code>
	 */
	public ProtocolFactory(PreSharedKeyProvider preSharedKeyProvider,
			ReceiverPrivateKeyProvider receiverPrivateKeyProvider)
	{
		this(preSharedKeyProvider, receiverPrivateKeyProvider, List.of(V1_SERIALIZER));
	}

	protected ProtocolFactory(PreSharedKeyProvider preSharedKeyProvider,
			ReceiverPrivateKeyProvider receiverPrivateKeyProvider,
			Collection<? extends ProtocolSerializer<? extends Protocol>> protocolSerializers)
	{
		this.preSharedKeyProvider = Objects.requireNonNull(preSharedKeyProvider, "preSharedKeyProvider");
		this.receiverPrivateKeyProvider = Objects.requireNonNull(receiverPrivateKeyProvider,
				"receiverPrivateKeyProvider");

		if (protocolSerializers != null)
		{
			this.protocolSerializers.addAll(protocolSerializers);

			if (protocolSerializers.size() != protocolSerializers.stream().mapToInt(ProtocolSerializer::getVersion)
					.distinct().count())
				throw new IllegalArgumentException("Multiple protocol serializers for same version");
		}
	}

	public Protocol read(InputStream source) throws IOException
	{
		Objects.requireNonNull(source, "source");

		byte[] baseHeaderValue = source.readNBytes(ROOT_HEADER_LENGTH);
		ByteEncoding.expectRead(ROOT_HEADER_LENGTH, baseHeaderValue.length);

		if (!Arrays.equals(MAGIC, 0, MAGIC.length, baseHeaderValue, 0, MAGIC.length))
			throw new IOException("Protocol not supported");

		int version = baseHeaderValue[baseHeaderValue.length - 1] & 0xFF;

		Optional<ProtocolSerializer<? extends Protocol>> deserializer = protocolSerializers.stream()
				.filter(s -> s.getVersion() == version).findFirst();
		if (deserializer.isPresent())
			return deserializer.get().read(source, preSharedKeyProvider, receiverPrivateKeyProvider);
		else
			throw new IOException("Protocol not supported");
	}

	public InputStream write(Protocol protocol)
	{
		Objects.requireNonNull(protocol, "protocol");

		Optional<ProtocolSerializer<? extends Protocol>> serializer = protocolSerializers.stream()
				.filter(s -> s.getType().isInstance(protocol)).findFirst();

		if (serializer.isPresent())
		{
			@SuppressWarnings("unchecked")
			ProtocolSerializer<Protocol> protocolSerializer = (ProtocolSerializer<Protocol>) serializer.get();

			return new ByteArrayInputStream(ByteEncoding.concat(MAGIC,
					ByteEncoding.i2osp1(protocolSerializer.getVersion()), protocolSerializer.write(protocol)));
		}
		else
			throw new IllegalArgumentException("Protocol not supported");
	}

	public PreSharedKeyProvider getPreSharedKeyProvider()
	{
		return preSharedKeyProvider;
	}

	public ReceiverPrivateKeyProvider getReceiverPrivateKeyProvider()
	{
		return receiverPrivateKeyProvider;
	}
}

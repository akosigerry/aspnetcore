// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Quic.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Server.Kestrel.Transport.Quic;

/// <summary>
/// A factory for QUIC based connections.
/// </summary>
internal sealed class QuicTransportFactory : IMultiplexedConnectionListenerFactory
{
    private readonly ILogger _log;
    private readonly QuicTransportOptions _options;

    public QuicTransportFactory(ILoggerFactory loggerFactory, IOptions<QuicTransportOptions> options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (loggerFactory == null)
        {
            throw new ArgumentNullException(nameof(loggerFactory));
        }

        var logger = loggerFactory.CreateLogger("Microsoft.AspNetCore.Server.Kestrel.Transport.Quic");
        _log = logger;
        _options = options.Value;
    }

    /// <summary>
    /// Binds an endpoint to be used for QUIC connections.
    /// </summary>
    /// <param name="endpoint">The endpoint to bind to.</param>
    /// <param name="features">Additional features to be used to create the listener.</param>
    /// <param name="cancellationToken">To cancel the </param>
    /// <returns>A </returns>
    public async ValueTask<IMultiplexedConnectionListener> BindAsync(EndPoint endpoint, IFeatureCollection? features = null, CancellationToken cancellationToken = default)
    {
        if (endpoint == null)
        {
            throw new ArgumentNullException(nameof(endpoint));
        }

        var tlsConnectionOptions = features?.Get<TlsConnectionOptions>();

        if (tlsConnectionOptions == null)
        {
            throw new InvalidOperationException("Couldn't find HTTPS configuration for QUIC transport.");
        }
        if (tlsConnectionOptions.ApplicationProtocols == null || tlsConnectionOptions.ApplicationProtocols.Count == 0)
        {
            throw new InvalidOperationException("No application protocols specified for QUIC transport.");
        }

        var transport = new QuicConnectionListener(_options, _log, endpoint, tlsConnectionOptions);
        await transport.CreateListenerAsync();

        return transport;
    }
}

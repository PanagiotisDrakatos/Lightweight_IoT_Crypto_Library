using SecureUWPChannel.Serialization;
using SecureUWPClient.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPChannel.Interfaces
{
    public abstract class IAsyncSynAck
    {
        abstract public Task SendPlainMessage();
        abstract public Task ReceiveServerCertificate();
        abstract public Task ResendCookieServer();
        abstract public Task SendPublicValue();
        abstract public Task ReceivePublicValue();
        abstract public Task SendCipherSuites();

        abstract public Task<CiphersForUse> ReceiveCipherSuites();
    }
}

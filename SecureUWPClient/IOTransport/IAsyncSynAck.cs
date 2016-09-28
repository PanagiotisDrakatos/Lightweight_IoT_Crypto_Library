using SecureUWPChannel.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPChannel.Interfaces
{
    public interface IAsyncSynAck<T>
    {
        Task SendPlainMessage(T obj);
        Task ReceiveServerCertificate(T obj);
        Task ResendCookieServer(T obj);
        Task SendPublicValue(T obj);

        Task ReceivePublicValue(T obj);
        Task SendCipherSuites(T obj);

        Task<String> ReceiveCipherSuites(T obj);
    }
}

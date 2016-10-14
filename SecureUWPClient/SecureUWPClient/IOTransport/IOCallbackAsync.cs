using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecureUWPChannel.Serialization;
using SecureUWPClient.Ciphers.AES;
using SecureUWPClient.Ciphers.Symmetric;

namespace SecureUWPChannel.Interfaces
{
    public abstract class IOCallbackAsync
    {
        abstract public Task SendDHEncryptedMessage(String Message, AES_CBC CBC);

        abstract public Task SendDHEncryptedMessage(String Message, AES_ECB ECB);
        abstract public Task<String> ReceiveDHEncryptedMessage(AES_CBC CBC);

        abstract public Task<String> ReceiveDHEncryptedMessage(AES_ECB ECB);
    }
}

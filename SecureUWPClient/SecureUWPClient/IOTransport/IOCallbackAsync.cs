using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecureUWPChannel.Serialization;

namespace SecureUWPChannel.Interfaces
{
    public abstract class IOCallbackAsync
    {
        abstract public Task SendDHEncryptedMessage(String Message);
        abstract public Task<String> ReceiveDHEncryptedMessage(String PublicKey);
    }
}

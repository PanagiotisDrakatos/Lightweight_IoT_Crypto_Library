using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography.Core;

namespace SecureUWPClient.Ciphers.RSA
{
    public interface RsaCiphers
    {
        Task<String> RsaEncrypt(CryptographicKey publicKey, String plainText);
    }
}

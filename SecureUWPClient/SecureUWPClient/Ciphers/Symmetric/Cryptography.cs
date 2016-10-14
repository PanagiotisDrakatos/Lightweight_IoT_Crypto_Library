using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPClient.Ciphers.Symmetric
{
     public interface  Cryptography
    {
          Task<String> AeS_Encrypt(String plaintext, String Key);

          Task<String> AeS_Decrypt(String encrypted, String Key);
    }
}

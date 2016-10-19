using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography.Core;

namespace SecureUWPClient.Configuration
{
   public class CiphersForUse
    {
        private String cipherAlgorithm;
        private String hashAlgorithm;


        public CiphersForUse()
        {
            this.cipherAlgorithm = null;
            this.hashAlgorithm = null;
        }

        public CiphersForUse(String cipherAlgorithm, String hashAlgorithm)
        {
            this.cipherAlgorithm = cipherAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
        }


        public string CipherAlgorithm
        {
            get
            {
                return cipherAlgorithm;
            }
            set
            {
                cipherAlgorithm = value;
            }
        }


        public string HashAlgorithm
        {
            get
            {
                if (hashAlgorithm.Contains("256"))
                    return MacAlgorithmNames.HmacSha256;
                else if(hashAlgorithm.Contains("SHA1"))
                    return MacAlgorithmNames.HmacSha1;
                else
                    return MacAlgorithmNames.HmacMd5;
            }
            set
            {
                hashAlgorithm = value;
            }
        }

        public override string ToString()
        {
            return base.ToString() + ": ";
        }
    }
}

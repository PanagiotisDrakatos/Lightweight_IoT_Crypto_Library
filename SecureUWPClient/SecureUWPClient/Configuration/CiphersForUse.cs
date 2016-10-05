using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
                return hashAlgorithm;
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

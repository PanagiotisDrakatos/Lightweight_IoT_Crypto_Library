using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPChannel.Serialization
{


    public class JSonObject
    {

        public String PlainMessage = "";
        public String PseudoNumber = "";
        public String CookieServer = "";
        public String CertPemFormat = "";

        public String ClientEncryptedPrimeNumber = "";
        public String ServerPrimeNumber = "";

        public String CipherSuites = "";
        public String EncryptedMessage = "";
        public String FingerPrint = "";
        public String HmacHash = "";
    }

}


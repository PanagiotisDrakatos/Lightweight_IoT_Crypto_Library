using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography.Certificates;
using Windows.Security.Cryptography.Core;

namespace SecureUWPClient.KeyManager
{
    public abstract class KeyManagerImp
    {

        protected String _clientFolder = "ClientStore";
        protected String _server_PUBLIC_KEY =  "Public.key";
        protected String _server_Certificate = "Certificate.pem";

        public abstract void SaveServerPublicKey(Certificate cert);

        public abstract Task<int> SaveCertificate(String CertPemFormat);

        public abstract Task<Certificate> LoadCertificate();

        public abstract Task<CryptographicKey> LoadPublicKey();

        public abstract void ProduceCipherKey(String SessionResult);

        public abstract void ProduceIntegrityKey(String SessionResult);

       // public abstract X509Certificate loadCertificate();

        public abstract Task<String> LoadCipherKey();

        public abstract Task<CryptographicKey> LoadIntegrityKey();

        public abstract String ClientFolder { get; }
        public abstract String Server_PUBLIC_KEY { get; }

        public abstract String Server_Certificate { get; }
    }
}

using SecureUWPChannel.Interfaces;
using SecureUWPChannel.IOTransport;
using SecureUWPChannel.Prooperties;
using SecureUWPClient.Ciphers.AES;
using SecureUWPClient.Ciphers.Symmetric;
using SecureUWPClient.Configuration;
using SecureUWPClient.KeyManager;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking.Sockets;

namespace SecureUWPClient.Handshake
{
    public class IOSessionBuilder
    {
        private CiphersForUse ciphersforUse;
        private IAsyncSynAck DHsession;
        private IOCallbackAsync messageExhange;
        private IOMulticastAndBroadcast Activity;
        private KeyManagerImp keystore;

        public IOSessionBuilder()
        {
            this.keystore = new KeyHandler();
            Activity = new IOMulticastAndBroadcast(SampleConfiguration.Host, SampleConfiguration.ConnectionPort);
        }
       public async Task InitializeAsync()
        {
            await Activity.connect();
            DHsession = new DHkeyExchange(Activity, this.keystore);
        }

        public async void  EstablishDHkeySession()
        {
        var t = Task.Run(async () => {
           long elapsed=ExecutionTime.CurrentTimeMillis();
           await DHsession.SendPlainMessage();
           await this.DHsession.ReceiveServerCertificate();
           await this.DHsession.ResendCookieServer();
           await this.DHsession.SendPublicValue();
           await this.DHsession.ReceivePublicValue();
           await this.DHsession.SendCipherSuites();
           ciphersforUse =  await this.DHsession.ReceiveCipherSuites();
           Debug.WriteLine("---------------Sum up Time------------------------ " + (ExecutionTime.CurrentTimeMillis() - elapsed));//900-1000ms
           messageExhange = new IOMessageExhange(Activity, ciphersforUse, this.keystore);
         });
         t.Wait();
        }

        public async Task<Object> ChooseCipher()
        {
            if(ciphersforUse.CipherAlgorithm.Contains("CBC", StringComparison.OrdinalIgnoreCase))
            {
                Cryptography CBC_Cipher=new AES_CBC(SupportedChipher.CBC);
                return CBC_Cipher;
            }
            else if(ciphersforUse.CipherAlgorithm.Contains("ECB", StringComparison.OrdinalIgnoreCase))
            {
                Cryptography ECB_Cipher = new AES_CBC(SupportedChipher.ECB);
                return ECB_Cipher;
            }
            else
            {
                return Convert.ChangeType(0, typeof(object)).GetType();
            }

        }
        public IOCallbackAsync MessageExhange
        {
            get
            {
                return messageExhange;
            }
            set
            {
                messageExhange = value;
            }
        }

    }
}

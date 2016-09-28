using System;
using System.Threading.Tasks;
using SecureUWPChannel.Interfaces;
using SecureUWPChannel.Serialization;
using SecureUWPChannel.Prooperties;
using SecureUWPClient.Configuration;
using SecureUWPClient.KeyManager;

namespace SecureUWPChannel.IOTransport
{
    public class DHkeyExchange :IAsyncSynAck<DHkeyExchange>
    {
        private IOMulticastAndBroadcast ActivitySocket;
        private JSonObject ReadObj;
        private JSonObject WriteObj;
        private PrimeNumberGenerator Genarator;
        private  KeyHandler keystore;

        public DHkeyExchange(IOMulticastAndBroadcast ActivitySocket)
        {
            this.keystore = new KeyHandler();
            this.ActivitySocket = ActivitySocket;
            this.Genarator = new PrimeNumberGenerator();
            Intialize();
        }
       

        public void Intialize()
        {
            ReadObj = new JSonObject();
            WriteObj = new JSonObject();
          
        }

        public async Task SendPlainMessage(DHkeyExchange keyExchange)
        {
            WriteObj.PlainMessage = SampleConfiguration.SYN;
            WriteObj.PseudoNumber = Genarator.pseudorandom();

            String toSend = JsonParse.WriteObject(WriteObj);
            await ActivitySocket.send(toSend);

        }

        public async Task ReceiveServerCertificate(DHkeyExchange keyExchange)
        {
            ReadObj = JsonParse.ReadObject(await ActivitySocket.read());
            String timestamp = Genarator.pseudorandom();
            if (!ReadObj.PlainMessage.Equals(SampleConfiguration.SYN_ACK) ||
                    !ReadObj.PseudoNumber.Equals(timestamp))
                throw new Exception("Server Cannot Be Verified");
            
               // this.keystore.SaveCertificate(receivedObj.CertPemFormat);
          //  cookie.setCookieServer(receivedObj.CookieServer);
        }

        public async Task ResendCookieServer(DHkeyExchange keyExchange)
        {

        }


        public async Task SendPublicValue(DHkeyExchange keyExchange)
        {

        }


        public async Task ReceivePublicValue(DHkeyExchange keyExchange)
        {

        }

        public async Task SendCipherSuites(DHkeyExchange keyExchange)
        {

        }

        public async Task<String> ReceiveCipherSuites(DHkeyExchange keyExchange)
        {
            return "";
        }

    }
}

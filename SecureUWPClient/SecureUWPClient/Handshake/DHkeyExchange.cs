using System;
using System.Threading.Tasks;
using SecureUWPChannel.Interfaces;
using SecureUWPChannel.Serialization;
using SecureUWPChannel.Prooperties;
using SecureUWPClient.Configuration;
using SecureUWPClient.KeyManager;
using SecureUWPClient.Ciphers.RSA;
using System.Diagnostics;
using SecureUWPClient.Ciphers.AES;

namespace SecureUWPChannel.IOTransport
{
    public class DHkeyExchange :IAsyncSynAck
    {
        private IOMulticastAndBroadcast ActivitySocket;
        private PrimeNumberGenerator Genarator;
        private KeyHandler keystore;
        private Cookie cOokie;
        private RSA_PKCS1 rsa_pkcs1;
        private JSonObject ReadObj;
        private JSonObject WriteObj;


        private string Ciphers;
        private string Diggest;
        private string CurrentDiggest;

        public DHkeyExchange(IOMulticastAndBroadcast ActivitySocket)
        {
            this.keystore = new KeyHandler();
            this.Genarator = new PrimeNumberGenerator();
            this.cOokie = new Cookie();
            this.rsa_pkcs1 = new RSA_PKCS1();
            this.ActivitySocket = ActivitySocket;
            Intialize();
        }
       

        public void Intialize()
        {
            ReadObj = new JSonObject();
            WriteObj = new JSonObject();
        }

        public override async Task SendPlainMessage()
        {
            WriteObj.PlainMessage = SampleConfiguration.SYN;
            WriteObj.PseudoNumber = Genarator.pseudorandom();

            String toSend = JsonParse.WriteObject(WriteObj);
            await ActivitySocket.send(toSend);

        }

        public override async Task ReceiveServerCertificate()
        {
            ReadObj = JsonParse.ReadObject(await ActivitySocket.read());
            String timestamp = Genarator.pseudorandom();
            if (!ReadObj.PlainMessage.Equals(SampleConfiguration.SYN_ACK) ||
                    !ReadObj.PseudoNumber.Equals(timestamp))
                throw new Exception("Server Cannot Be Verified");
            
            var t = Task.Run(async () => {
                await keystore.SaveCertificate(ReadObj.CertPemFormat);
            });
            t.Wait();

            await Task.Delay(TimeSpan.FromMilliseconds(20));
            t = Task.Run(async () => {
                keystore.SaveServerPublicKey(await keystore.LoadCertificate());
            });
            t.Wait();

            cOokie.CookieServer=ReadObj.CookieServer;
        }

        public override async Task ResendCookieServer()
        {
            WriteObj = new JSonObject();
            WriteObj.PlainMessage = SampleConfiguration.Replay;
            WriteObj.PseudoNumber = Genarator.pseudorandom();
            WriteObj.CookieServer = cOokie.CookieServer;

            String toSend = JsonParse.WriteObject(WriteObj);
            await ActivitySocket.send(toSend);
            return;
        }


        public override async Task SendPublicValue()
        {
            String ServerPublicPrimeNumber = Genarator.GetClientPublicNumber();
            try
            {
                WriteObj = new JSonObject();
                WriteObj.PseudoNumber = Genarator.pseudorandom();
                String encrypted= await rsa_pkcs1.RsaEncrypt(await keystore.LoadPublicKey(),ServerPublicPrimeNumber);
                WriteObj.ClientEncryptedPrimeNumber = encrypted;

                String toSend = JsonParse.WriteObject(WriteObj);
                await ActivitySocket.send(toSend);
                return;
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
            }
        }


        public override async Task ReceivePublicValue()
        {
            ReadObj = JsonParse.ReadObject(await ActivitySocket.read());
            if (!ReadObj.PseudoNumber.Equals(Genarator.pseudorandom()))
                throw new Exception("Server Cannot Be Verified Possible Replay Attack");

            String sessionResult = Genarator.SessionDHGenerator(ReadObj.ServerPrimeNumber);
            keystore.ProduceCipherKey(sessionResult);//Produce and save Ciphers Key from The given Session Result
            keystore.ProduceIntegrityKey(sessionResult);//Produce and save Integrity Key from The given Session Result
            Debug.WriteLine(sessionResult);
            return;
        }

        public override async Task SendCipherSuites()
        {
            WriteObj = new JSonObject();

             Ciphers = StringJoin.Joiner(",",SampleConfiguration.AES_ECB, SampleConfiguration.AES_CBC);
             Diggest = StringJoin.Joiner(",", SampleConfiguration.MD5, SampleConfiguration.sha1, SampleConfiguration.MACSHA_256);
             CurrentDiggest = StringJoin.Joiner(",", SampleConfiguration.MACSHA_256);
            string joiner = StringJoin.Joiner("|", Ciphers, Diggest, CurrentDiggest);

            WriteObj.PseudoNumber = Genarator.pseudorandom();
            WriteObj.CipherSuites = joiner;
            WriteObj.HmacHash = HMacAlgoProvider.CreateHMAC(joiner, await keystore.LoadIntegrityKey(), CurrentDiggest);

            String toSend = JsonParse.WriteObject(WriteObj);
            await ActivitySocket.send(toSend);
            return;
        }

        public override async Task<CiphersForUse> ReceiveCipherSuites()
        {
            ReadObj = JsonParse.ReadObject(await ActivitySocket.read());
            if (!ReadObj.PseudoNumber.Equals(Genarator.pseudorandom()) ||
                !HMacAlgoProvider.VerifyHMAC(ReadObj.CipherSuites, await keystore.LoadIntegrityKey(), ReadObj.HmacHash, CurrentDiggest))
                throw new Exception("Server Cannot Be Verified Possible Replay Attack");


            String SelectedCiphers = ReadObj.CipherSuites;
            Debug.WriteLine(SelectedCiphers);
            String[] parts = null;

            if (SelectedCiphers.Contains("|"))
                parts = SelectedCiphers.Split('|');
            else
                throw new Exception("String " + SelectedCiphers + " does not contain |");

            //   System.out.println(parts.toString());
            String CipherAlgo = parts[0];
            String HashAlgo = parts[1];
            return new CiphersForUse(CipherAlgo, HashAlgo);
        }

    }
}

using SecureUWPChannel.Interfaces;
using SecureUWPChannel.IOTransport;
using SecureUWPChannel.Serialization;
using SecureUWPClient.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPClient.Handshake
{

    public class IOMessageExhange: IOCallbackAsync
    {

        private IOMulticastAndBroadcast ActivitySocket;
        private CiphersForUse ciphersforUse;


        private JSonObject ReadObj;
        private JSonObject WriteObj;

        public IOMessageExhange(IOMulticastAndBroadcast ActivitySocket, CiphersForUse ciphersforUse)
        {
            this.ActivitySocket = ActivitySocket;
            this.ciphersforUse = ciphersforUse;
            Intialize();
        }

        public void Intialize()
        {
            ReadObj = new JSonObject();
            WriteObj = new JSonObject();
        }

        public override Task<string> ReceiveDHEncryptedMessage(string PublicKey)
        {
            throw new NotImplementedException();
        }

        public override Task SendDHEncryptedMessage(string Message)
        {
            throw new NotImplementedException();
        }
    }
}

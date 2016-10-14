using SecureUWPChannel.Interfaces;
using SecureUWPChannel.IOTransport;
using SecureUWPChannel.Prooperties;
using SecureUWPChannel.Serialization;
using SecureUWPClient.Ciphers.AES;
using SecureUWPClient.Ciphers.RSA;
using SecureUWPClient.Ciphers.Symmetric;
using SecureUWPClient.Configuration;
using SecureUWPClient.KeyManager;
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
        private KeyManagerImp keystore;


        private JSonObject ReadObj;
        private JSonObject WriteObj;

        public IOMessageExhange(IOMulticastAndBroadcast ActivitySocket, CiphersForUse ciphersforUse, KeyManagerImp keystore)
        {
            this.ActivitySocket = ActivitySocket;
            this.ciphersforUse = ciphersforUse;
            this.keystore = keystore;
            Intialize();
        }

        public void Intialize()
        {
            ReadObj = new JSonObject();
            WriteObj = new JSonObject();
        }

        public override async Task SendDHEncryptedMessage(string Message, AES_CBC CBC)
        {
            WriteObj = new JSonObject();
            String encrypted = await CBC.AeS_Encrypt(Message, await keystore.LoadCipherKey());
            WriteObj.EncryptedMessage = encrypted;
            WriteObj.HmacHash = HMacAlgoProvider.CreateHMAC(encrypted, await keystore.LoadIntegrityKey(), ciphersforUse.HashAlgorithm);
            // System.out.println(ObjToSend.EncryptedMessage);

            String toSend = JsonParse.WriteObject(WriteObj);
            await this.ActivitySocket.send(toSend);
            return;
        }

        public override async Task SendDHEncryptedMessage(string Message, AES_ECB ECB)
        {
            WriteObj = new JSonObject();
            String encrypted = await ECB.AeS_Encrypt(Message, await keystore.LoadCipherKey());
            WriteObj.EncryptedMessage = encrypted;
            WriteObj.HmacHash = HMacAlgoProvider.CreateHMAC(encrypted, await keystore.LoadIntegrityKey(), ciphersforUse.HashAlgorithm);
            // System.out.println(ObjToSend.EncryptedMessage);

            String toSend = JsonParse.WriteObject(WriteObj);
            await this.ActivitySocket.send(toSend);
            return;
        }

        public override async Task<string> ReceiveDHEncryptedMessage(AES_CBC CBC)
        {
            ReadObj = JsonParse.ReadObject(await this.ActivitySocket.read());
            if (Fingerprint.VerifySignature(ReadObj.EncryptedMessage, await keystore.LoadPublicKey(), ReadObj.FingerPrint))
            {
                if (HMacAlgoProvider.VerifyHMAC(ReadObj.EncryptedMessage, await keystore.LoadIntegrityKey(), ReadObj.HmacHash,
                        ciphersforUse.HashAlgorithm))
                {
                    return await CBC.AeS_Decrypt(ReadObj.EncryptedMessage,
                           await keystore.LoadCipherKey());
                }
                else {
                    throw new Exception("Integrity of SymmetricKey canot verified");
                }
            }
            else {
                throw new Exception("Integrity of RSA canot verified");
            }
        }


        public override async Task<string> ReceiveDHEncryptedMessage(AES_ECB ECB)
        {
            ReadObj = JsonParse.ReadObject(await this.ActivitySocket.read());
            if (Fingerprint.VerifySignature(ReadObj.EncryptedMessage, await keystore.LoadPublicKey(), ReadObj.FingerPrint))
            {
                if (HMacAlgoProvider.VerifyHMAC(ReadObj.EncryptedMessage, await keystore.LoadIntegrityKey(), ReadObj.HmacHash,
                        ciphersforUse.HashAlgorithm))
                {
                    return await ECB.AeS_Decrypt(ReadObj.EncryptedMessage,
                           await keystore.LoadCipherKey());
                }
                else {
                    throw new Exception("Integrity of SymmetricKey canot verified");
                }
            }
            else {
                throw new Exception("Integrity of RSA canot verified");
            }
        }

    }
}

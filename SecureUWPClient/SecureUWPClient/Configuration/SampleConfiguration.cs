using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Windows.Security.Cryptography.Core;
using Windows.Storage;

namespace SecureUWPChannel.Prooperties
{
    public class SampleConfiguration
    {
        //socket properties
        public static  String ConnectionPort = "1337";
        public static  int MaxConnections = 100;
        public static  int timeout = 420000;
        public static String Host = "192.168.1.67";

        public static String SYN = "ClientHello";
        public static  String SYN_ACK = "ServerHello";
        public static  String Replay = "Resend";

        //encryption properties  
        public static String strSecret = "PutAStrongPassword";
        public static String MacAlg = MacAlgorithmNames.HmacSha256;
        public static String SymetrricAlgorithm = SymmetricAlgorithmNames.AesCbcPkcs7;

        //Put your Message to send to server
        public static String Messages = "Hello Server :D";
             
        //for more info check https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
        //g^x mod p 
        //However, its very unlikely that anyone else listening on the channel 
        //can calculate the key, since the calculation of discrete logarithms under 
        //field arithmetic is very hard (see Galois Fields)
        //Prime numbers machine generator 
        public static  String exponent = "67849492012064603525502413864581601255843190582896059031333969517102908698009";
        public static  String modulus = "71121776095154293411645315316982820283937449209225990596316112319337209629611";


        public static  String AES_PROVIDER = "AES";
        public static  String AES_ECB = "AES/ECB/PKCS7Padding";
        public static  String AES_CBC = "AES/CBC/PKCS7Padding";

        public static  String MD5 = "md5";
        public static  String sha1 = "SHA-1";
        public static  String SHA_256 = "SHA-256";
        public static  String MACSHA_256 = MacAlgorithmNames.HmacSha256;

        public const string SampleBackgroundTaskEntryPoint = "Tasks.SampleBackgroundTask";
        public const string SampleBackgroundTaskName = "SampleBackgroundTask";
        public static string SampleBackgroundTaskProgress = "";
        public static bool SampleBackgroundTaskRegistered = false;

      

        public const string TimeTriggeredTaskName = "TimeTriggeredTask";
        public static string TimeTriggeredTaskProgress = "";
        public static bool TimeTriggeredTaskRegistered = false;

        public const string ApplicationTriggerTaskName = "ApplicationTriggerTask";
        public static string ApplicationTriggerTaskProgress = "";
        public static string ApplicationTriggerTaskResult = "";
        public static bool ApplicationTriggerTaskRegistered = false;

     
        public static bool TaskRequiresBackgroundAccess(String name)
        {
            if ((name == TimeTriggeredTaskName) ||
                (name == ApplicationTriggerTaskName))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}

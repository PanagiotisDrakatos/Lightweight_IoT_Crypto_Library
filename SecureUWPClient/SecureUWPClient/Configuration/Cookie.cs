using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPClient.Configuration
{
   public class Cookie
    {
        private String cookieServer;
        private String DEF_RANDOM_ALGORITHM = "SHA1PRNG";
        private  int seedByteCount = 10;

        public string CookieServer
        {
            get
            {
                return cookieServer;
            }
            set
            {
                cookieServer = value;
            }
        }

        public int SeedByteCount
        {
            get
            {
                return seedByteCount;
            }
            set
            {
                seedByteCount = value;
            }
        }


        public string Algorithm
        {
            get
            {
                return DEF_RANDOM_ALGORITHM;
            }
            set
            {
                DEF_RANDOM_ALGORITHM = value;
            }
        }

        public override string ToString()
        {
            return base.ToString() + ": ";
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPClient.Configuration
{
    public class ExecutionTime
    {
        private static readonly DateTime CurrentDat = DateTime.Now;

        public static long CurrentTimeMillis()
        {
            return (long)(DateTime.UtcNow - CurrentDat).TotalMilliseconds;
        }
    }
}

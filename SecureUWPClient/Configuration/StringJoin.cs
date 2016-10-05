using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPClient.Configuration
{
   public class StringJoin
    {
        public static string Concat(params string[] strings)
        {
            return String.Concat(strings);
        }

        public  static string Format(params string[] strings)
        {
            return string.Format("{0}{1}{2}", strings);
        }

        public static string Pluses(params string[] strings)
        {
            return strings[0] + strings[1] + strings[2];
        }

        public static string Builder(params string[] strings)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(strings[0]);
            sb.Append(strings[1]);
            sb.Append(strings[2]);
            return sb.ToString();
        }

        public static string Joiner(string symbol,params string[] strings)
        {
            return string.Join(symbol, strings);
        }
    }
}

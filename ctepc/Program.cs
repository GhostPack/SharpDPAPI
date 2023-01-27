using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ctepc
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0) {

            }
        }

        static void ExtractPasswordsFromChrome()
        {
            SharpChrome.Program.Main(new [] { "loginsexport", "/format:csv", "/browser:chrome" });
        }

        static void WritePasswordsToEdge()
        {

        }
    }
}

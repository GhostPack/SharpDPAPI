using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestLoginsExportCommandChrome()
        {
            SharpChrome.Program.Main(new [] { "loginsexport", "/format:csv", "/browser:chrome" });
        }

        [TestMethod]
        public void TestShowUsage()
        {
            using var consoleOutput = Console.OpenStandardOutput(255);
            SharpChrome.Program.Main(new [] { "help" });
        }

        [TestMethod]
        public void TestGetLoginCommandChrome()
        {
            SharpChrome.Program.Main(new [] { "logins", "/format:csv", "/browser:chrome" });
        }
    }
}

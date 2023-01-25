using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            SharpChrome.Program.Main(new [] { "logins", "/format:csv", "/browser:edge" });
        }
    }
}

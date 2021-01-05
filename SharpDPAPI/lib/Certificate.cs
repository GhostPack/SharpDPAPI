using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpDPAPI
{
    public class ExportedCertificate
    {
        public ExportedCertificate()
        {
            Subject = "";
            Issuer = "";
            ValidDate = "";
            ExpiryDate = "";
            PrivateKey = "";
            PublicCertificate = "";
            Thumbprint = "";
            EKUs = new List<Tuple<string, string>>();
        }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public string ValidDate { get; set; }
        public string ExpiryDate { get; set; }
        public string PrivateKey { get; set; }
        public string PublicCertificate { get; set; }
        public string Thumbprint { get; set; }
        public List<Tuple<string, string>> EKUs { get; set; }
    }
}

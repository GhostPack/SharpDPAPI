using System;
using System.Management;

namespace SharpChrome
{
    class Vsscopy
    {
        //Reference to https://learn.microsoft.com/zh-cn/previous-versions/windows/desktop/legacy/aa394428(v=vs.85)?redirectedfrom=MSDN
        public static string CreateShadow(string volumePath = "C:\\")
        {
            string shadowCopyID = string.Empty;
            try
            {
                ManagementClass shadowCopyClass = new ManagementClass(new ManagementPath("Win32_ShadowCopy"));
                ManagementBaseObject inParams = shadowCopyClass.GetMethodParameters("Create");

                inParams["Volume"] = volumePath;

                ManagementBaseObject outParams = shadowCopyClass.InvokeMethod("Create", inParams, null);
                shadowCopyID = outParams["ShadowID"].ToString();
                return shadowCopyID;
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] {0}", e.InnerException.Message);
                return null;
            }
        }

        public static string ListShadow(string shadowCopyID)
        {
            string DeviceObject = string.Empty;
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ShadowCopy WHERE ID='" + shadowCopyID + "'");
                ManagementObjectCollection shadowCopies = searcher.Get();

                foreach (ManagementObject shadowCopy in shadowCopies)
                {
                    DeviceObject = shadowCopy.GetPropertyValue("DeviceObject").ToString();
                }
                return DeviceObject;
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] {0}", e.InnerException.Message);
                return null;
            }
        }

        public static void DeleteShadow(string ShadowID)
        {
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ShadowCopy WHERE ID='" + ShadowID + "'");
                ManagementObjectCollection shadowCopies = searcher.Get();

                foreach (ManagementObject shadowCopy in shadowCopies)
                {
                    shadowCopy.Delete();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] {0}", e.InnerException.Message);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace rsoni.UtilsLibrary
{
    #region How to use in Console App
    /*
     * Here is how to Use in Console App
     *   App.config 
   
   <appSettings>
    <add key="EnableLog" value="true" />
    <add key="LogFolder" value="" />
    <add key="LogFilePrefix" value="UnityPOC" />
  </appSettings>

        Program.cs
        static void Main(string[] args)
        {
            string executionMode = "Release";
#if DEBUG
            executionMode = "Debug";
#endif
            try
            {
                Console.ForegroundColor = ConsoleColor.White;
                Utility.LogEntry("--------------------------------------  Application Started [" + executionMode + "] ------------------------------------------------------");
                DateTime start = DateTime.Now;

                // Add your Code here for Testing 


                Console.ForegroundColor = ConsoleColor.White;
                Utility.LogEntry("Total Completion Duration in (ms):  " + (DateTime.Now - start).TotalMilliseconds);
                Utility.LogEntry2(string.Format("Successfully Completed."));

            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Utility.LogEntry(string.Format("Exception : {0} , Stack Trace: {1}", ex.Message, Utility.GetFullException(ex)));
                Utility.LogEntry(string.Format("Failed."));
                Console.ForegroundColor = ConsoleColor.White;
            }
            // If working in debug mode , need to see the output at console so let it wait there.
            if (System.Diagnostics.Debugger.IsAttached)
            {
                Console.Write("\nPress any key to exit... ");
                Console.ReadKey(true);
            }
            Console.Write("\nPress any key to exit... ");
            Console.ReadKey(true);
            Console.Write("\nPress any key to exit... ");
            Console.ReadKey(true);
        }





     
         */

    #endregion

    public static class Utility
    {

        private static string logFile = string.Empty;
        private static bool _enableLogging = true;

        public static List<string> ParseJSON(string jsonString)
        {
            var output = jsonString.Split(new[] { '{', '}' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => "{" + x + "}")
                    .ToList();

            return output;
        }


        /// <summary>
        /// Get LogFolder path
        /// </summary>
        /// <returns></returns>
        public static string GetLogFolder()
        {
            string logFolder = @"C:\logs\";
            string enableLogConfigEntry = GetConfigEntry("EnableLog");
            if (string.IsNullOrEmpty(enableLogConfigEntry))
                enableLogConfigEntry = "true";

            logFolder = GetConfigEntry("LogFolder");
            if (string.IsNullOrEmpty(logFolder))
            {
                //  logFolder = System.IO.Directory.GetCurrentDirectory();
                logFolder = AppDomain.CurrentDomain.BaseDirectory;
            }

            if (enableLogConfigEntry.ToLower().Equals("true"))
            {
                _enableLogging = true;
                if (!Directory.Exists(logFolder))
                {
                    Directory.CreateDirectory(logFolder);
                }
            }
            return logFolder;
        }

        /// <summary>
        /// Get log file prefix for log creation.
        /// </summary>
        /// <returns></returns>
        private static string GetLogFilePrefix()
        {
            string logFilePrefix = GetConfigEntry("LogFilePrefix");
            if (string.IsNullOrEmpty(logFilePrefix))
            {
                logFilePrefix = "ConsoleLog";
            }

            return logFilePrefix;
        }


        /// <summary>
        /// Get the config Entry
        /// </summary>
        /// <param name="AppSettingKey"></param>
        /// <returns></returns>
        public static string GetConfigEntry(string AppSettingKey)
        {
            string configEntryString = string.Empty;
            try
            {
                configEntryString = ConfigurationManager.AppSettings[AppSettingKey];
                if (string.IsNullOrEmpty(configEntryString))
                {
                    configEntryString = "";
                }
                else
                {
                    configEntryString = Convert.ToString(ConfigurationManager.AppSettings[AppSettingKey]);
                    //If config string value start with #$# then decrpt the string first.it can be password of secure information.
                    if (configEntryString.StartsWith("#$#"))
                    {
                        configEntryString = EncryptDecryptString.Decrypt(configEntryString.Substring(3));
                    }
                }
            }
            catch (Exception ex)
            {
                // No catch for exception.
            }

            return configEntryString;
        }

        static ReaderWriterLock FileLock = new ReaderWriterLock();
        /// <summary>
        /// Log entry method to add one entry in log file.
        /// </summary>
        /// <param name="logMsg"></param>
        public static void LogEntry2(string logMsg)
        {
            FileLock.AcquireWriterLock(60000);
            logMsg = "Time:" + DateTime.Now.ToShortTimeString() + " - " + logMsg;
            if (string.IsNullOrEmpty(logFile))
            {
                logFile = GetLogFolder() + GetLogFilePrefix() + ".log";
                if (File.Exists(logFile))
                {
                    DateTime creationDateTime = File.GetCreationTime(logFile);
                    // System.TimeSpan diff = DateTime.Now.Subtract(creationDateTime);
                    //if (diff.Days > 1)
                    // Check if just the Date is changed so that even at 11 pm in night will go in different file.
                    if (DateTime.Now.ToString("yyyyMMdd") != creationDateTime.ToString("yyyyMMdd"))
                    {
                        File.Copy(logFile, GetLogFolder() + GetLogFilePrefix() + "_" + DateTime.Now.ToString("yyyyMMddHHmmss") + ".log");
                        // This logic is just to set creation date and time for file.
                        File.Delete(logFile);
                    }
                }
            }

            if (_enableLogging)
            {
                bool setCreationTime = false;

                Object thisLock = new Object();
                lock (thisLock)
                {
                    if (File.Exists(logFile) == false)
                        setCreationTime = true;
                    StreamWriter logWriter = new StreamWriter(logFile, true);
                    logWriter.WriteLine(logMsg);
                    logWriter.Flush();
                    logWriter.Close();
                    logWriter.Dispose();
                    if (setCreationTime)
                        File.SetCreationTime(logFile, DateTime.Now);
                }
            }
            FileLock.ReleaseWriterLock();

        }
        /// <summary>
        /// Log entry for console and file both.
        /// </summary>
        /// <param name="logMsg"></param>
        public static void LogEntry(string logMsg)
        {
            LogEntry2(logMsg);
            Console.WriteLine(logMsg);
        }

        #region XML Methods
        public static string writeDataSetToXML(DataSet ds)
        {
            StringWriter sw = new StringWriter();
            string result = "";
            try
            {
                ds.WriteXml(sw, XmlWriteMode.WriteSchema);
                result = sw.ToString();
            }
            catch
            {

            }

            return result;
        }
        public static DataSet readXMLToDataSet(string xmlString)
        {
            DataSet dsXML = new DataSet();
            try
            {
                StringReader strRead = new StringReader(xmlString);
                dsXML.ReadXml(strRead, XmlReadMode.ReadSchema);
            }
            catch
            {

            }
            return dsXML;
        }
        #endregion

        #region DB MEthods

        public static DataSet GetDataSet(string query)
        {
            DataSet ds = new DataSet();
            SqlConnection Conn = new SqlConnection(Utility.GetConfigEntry("DBConnection"));
            Conn.Open();
            SqlDataAdapter DA = new SqlDataAdapter(query, Conn);
            DA.Fill(ds);
            if (Conn.State == ConnectionState.Open)
            {
                Conn.Close();
            }
            return ds;
        }

        public static void UpdateRecords(string query)
        {
            SqlConnection Conn = new SqlConnection(Utility.GetConfigEntry("DBConnection"));
            SqlCommand command = new SqlCommand(query, Conn);
            command.Connection.Open();
            command.ExecuteNonQuery();
            if (Conn.State == ConnectionState.Open)
            {
                Conn.Close();
            }
        }

        #endregion

        #region Date Time Methods

        /// <summary>
        /// convert the date time in YYYY MM DD HHmm format.
        /// </summary>
        /// <param name="dt"></param>
        /// <returns></returns>
        public static string ToDateTimeinYYYYMMDDhhmm(this DateTime dt)
        {
            return dt.ToString("yyyyMMddHHmm");
        }

        public static string ToDateTimeinYYYYMMDDhhmmss(this DateTime dt)
        {
            return dt.ToString("yyyyMMddHHmmss");
        }

        /// <summary>
        /// Get the DAte and Time in GMT format string.
        /// </summary>
        /// <param name="dt"></param>
        /// <returns></returns>
        public static string ToDateTimeGMTFormat(this DateTime dt)
        {
            return dt.ToString("yyyyMMddTHHmmss.fff") + " GMT";
        }
        /// <summary>
        /// get date time from string 
        /// </summary>
        /// <param name="yyyyMMddHHmm"></param>
        /// <returns></returns>
        public static DateTime GetDateTimeFromString(string yyyyMMddHHmm)
        {
            return GetDateTimeFromString(yyyyMMddHHmm, DateTime.MinValue);
        }

        /// <summary>
        /// Get the data time variable value from string format.
        /// </summary>
        /// <param name="yyyyMMddHHmm"></param>
        /// <returns></returns>
        public static DateTime GetDateTimeFromString(string yyyyMMddHHmm, DateTime DefaultValue)
        {
            DateTime dt = DateTime.MinValue;
            int yy = 0, mm = 0, dd = 0, hh = 0, min = 0;

            if (yyyyMMddHHmm.Length >= 4)
                yy = Converrt.ToInt(yyyyMMddHHmm.Substring(0, 4));
            if (yyyyMMddHHmm.Length >= 6)
                mm = Converrt.ToInt(yyyyMMddHHmm.Substring(4, 2));
            if (yyyyMMddHHmm.Length >= 8)
                dd = Converrt.ToInt(yyyyMMddHHmm.Substring(6, 2));
            if (yyyyMMddHHmm.Length >= 10)
                hh = Converrt.ToInt(yyyyMMddHHmm.Substring(8, 2));
            if (yyyyMMddHHmm.Length >= 12)
                min = Converrt.ToInt(yyyyMMddHHmm.Substring(10, 2));

            if (yy == 0 || mm == 0 || dd == 00)
                dt = DefaultValue;
            else
                dt = new DateTime(yy, mm, dd, hh, min, 0);

            return dt;
        }

        #endregion

        #region Error Handling
        /// <summary>
        /// Get the details of full exception 
        /// </summary>
        /// <returns></returns>
        public static string GetFullException(Exception ex)
        {
            string exceptionMsgandTrace = "";
            int counter = 0;
            Exception tempEx = ex;
            string innnerExceptionErrorMsg = tempEx.Message;
            while (innnerExceptionErrorMsg != string.Empty)
            {
                exceptionMsgandTrace = exceptionMsgandTrace + Environment.NewLine + "-------------------" + Environment.NewLine;
                exceptionMsgandTrace = exceptionMsgandTrace + " , Message : " + tempEx.Message + " StackTrace: " + tempEx.StackTrace;
                exceptionMsgandTrace = exceptionMsgandTrace + Environment.NewLine + "-------------------" + Environment.NewLine;
                tempEx = tempEx.InnerException;
                if (tempEx != null)
                    innnerExceptionErrorMsg = tempEx.Message;
                else
                    innnerExceptionErrorMsg = string.Empty;
                counter++;
                if (counter > 20) break;
            }

            return exceptionMsgandTrace;
        }
        #endregion

        #region doEvent
        public static void DoEvents()
        {
            //  Application.Current.Dispatcher.Invoke(DispatcherPriority.Background,                                                 new Action(delegate { }));
        }
        #endregion

    }

    public class Converrt
    {
        /// <summary>
        /// method to handle the null value while converting into string.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static string ToString(object obj)
        {
            string returnValue = string.Empty;
            if (obj != null)
                returnValue = Convert.ToString(obj);
            return returnValue;
        }

        /// <summary>
        /// method to handle the int conversion.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static int ToInt(object obj)
        {
            return ToInt(Convert.ToString(obj));
        }
        /// <summary>
        /// method to handle the int conversion.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static int ToInt(string str)
        {
            int returnValue = 0;
            string newstr = str;
            if (string.IsNullOrEmpty(str))
                newstr = "0";
            if (newstr.IndexOf(".") > 0)
                newstr = str.Substring(0, str.IndexOf("."));
            int outNumber;
            bool res = int.TryParse(newstr, out outNumber);
            if (res)
                returnValue = outNumber;
            return returnValue;
        }

        public static decimal ToDecimal(object obj)
        {
            return ToDecimal(Convert.ToString(obj));
        }
        /// <summary>
        /// method to handle the decimal conversion.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static decimal ToDecimal(string str)
        {
            decimal returnValue = 0;
            decimal outNumber;
            bool res = decimal.TryParse(str, out outNumber);
            if (res)
                returnValue = outNumber;
            return returnValue;
        }

        /// <summary>
        /// method to handle the int conversion.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static bool ToBoolean(object obj)
        {
            bool returnValue = false;

            bool outBoolean;
            bool res = bool.TryParse(ToString(obj), out outBoolean);
            if (res)
                returnValue = outBoolean;
            return returnValue;
        }

        /// <summary>
        /// method to handle the int conversion.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static DateTime ToDateTime(object obj, DateTime defaultValue)
        {
            DateTime returnValue = defaultValue;

            DateTime outDateTime;
            bool res = DateTime.TryParse(ToString(obj), out outDateTime);
            if (res)
                returnValue = outDateTime;

            if (returnValue == defaultValue)
                returnValue = ToDateTimeFromGMTFormat(obj, defaultValue);

            return returnValue;
        }

        /// <summary>
        /// Convert from GMT To Date time. '20140421T 071939.000 GMT'
        /// </summary>
        /// <returns></returns>
        public static DateTime ToDateTimeFromGMTFormat(object obj, DateTime defaultValue)
        {
            DateTime returnValue = defaultValue;

            string str = Converrt.ToString(obj);

            int yyyy = 0;
            int MM = 0;
            int dd = 0;
            int HH = 0;
            int min = 0;
            int ss = 0;

            if (str.Length > 4)
                yyyy = Converrt.ToInt(str.Substring(0, 4));
            if (str.Length > 6)
                MM = Converrt.ToInt(str.Substring(4, 2));
            if (str.Length > 8)
                dd = Converrt.ToInt(str.Substring(6, 2));

            if (str.Length > 10)
                HH = Converrt.ToInt(str.Substring(9, 2));
            if (str.Length > 11)
                min = Converrt.ToInt(str.Substring(11, 2));
            if (str.Length > 13)
                ss = Converrt.ToInt(str.Substring(13, 2));

            if (yyyy > 0 && MM > 0 && dd > 0)
                returnValue = new DateTime(yyyy, MM, dd, HH, min, ss);

            return returnValue;
        }
        /// <summary>
        /// method to handle the int conversion.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static DateTime ToDateTime(object obj)
        {
            return ToDateTime(obj, DateTime.MaxValue);
        }


    }


    public static class ExtendedMethods
    {

        /// <summary>
        /// This method returns the index of the nth occurence of the value passed in the specified string
        /// </summary>
        /// <param name="target">The String in which search has to be done</param>
        /// <param name="value">The value of which occurence's index to be found</param>
        /// <param name="n">the occurence number for which the index will be returned</param>
        /// <returns></returns>
        public static int NthIndexOf(this string target, string value, int n)
        {
            Match m = Regex.Match(target, "((" + value + ").*?){" + n + "}");

            if (m.Success)
                return m.Groups[2].Captures[n - 1].Index;
            else
                return -1;
        }

        public static string GetFileName(this string fileNamewithPath)
        {
            string returnString = string.Empty;
            int startindex = fileNamewithPath.LastIndexOf("\\");
            returnString = fileNamewithPath.Substring(startindex + 1);
            return returnString;
        }

        public static byte[] GetBytes(this string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        /// <summary>
        /// Encode XML
        /// </summary>
        /// <param name="target"></param>
        /// <returns></returns>
        public static string EncodeXML(this string target)
        {
            return target.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&apos;");
        }

        /// <summary>
        /// Encode the XML replace chars
        /// </summary>
        /// <param name="target"></param>
        /// <returns></returns>
        public static string DecodeXML(this string target)
        {
            return target.Replace("&amp;", "&").Replace("&lt;", "<").Replace("&gt;", ">").Replace("&quot;", "\"").Replace("&apos;", "'");
        }


        /// <summary>
        /// En codidng
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static string Base64Encode(this string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }


        public static string Base64Decode(this string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

    }

    public static class EncryptDecryptString
    {
        private static byte[] key = { };
        private static byte[] IV = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };  //
        private const string CONST_EncryptionKey = "ABCD1234";

        #region Not in use
        public static string TripleDESDecrypt(string encryptedString)
        {
            TripleDESCryptoServiceProvider cp = new TripleDESCryptoServiceProvider();
            MemoryStream m = new MemoryStream(Convert.FromBase64String(encryptedString));

            cp.Key = Convert.FromBase64String("BeaYzNeHfDb27OFYgaYHUd5HUJE2aZyI");
            cp.IV = Convert.FromBase64String("T/ENF5G4sCA=");

            CryptoStream cs = new CryptoStream(m, cp.CreateDecryptor(cp.Key, cp.IV), CryptoStreamMode.Read);

            StreamReader reader = new StreamReader(cs);
            string plainText = reader.ReadToEnd();
            return plainText;
        }
        public static string AESDatabaseDecrypt(string encryptedString)
        {
            string passphrase = "S0meFakePassPhrase01234!";
            encryptedString = "AQAAAOmuc52dnbVwTqEx1kp+4WhI89LYKHh3jg=="; // temporarily hard coded


            // setup encryption settings to match decryptbypassphrase
            TripleDESCryptoServiceProvider provider = new TripleDESCryptoServiceProvider();
            provider.Key = UTF8Encoding.UTF8.GetBytes(passphrase).Take(16).ToArray(); // stuck on getting key from passphrase
            provider.KeySize = 128;
            provider.Padding = PaddingMode.Zeros;
            // setup data to be decrypted
            byte[] encryptedStringAsByteArray = Convert.FromBase64String(encryptedString);

            // hack some extra bytes up to a multiple of 8
            encryptedStringAsByteArray = encryptedStringAsByteArray.Concat(new byte[] { byte.MinValue, byte.MinValue, byte.MinValue, byte.MinValue }).ToArray(); // add 4 empty bytes to make 32 bytes
            MemoryStream encryptedStringAsMemoryStream = new MemoryStream(encryptedStringAsByteArray);
            // decrypt
            CryptoStream cryptoStream = new CryptoStream(encryptedStringAsMemoryStream, provider.CreateDecryptor(), CryptoStreamMode.Read);
            // return the result
            StreamReader cryptoStreamReader = new StreamReader(cryptoStream);
            string decryptedString = cryptoStreamReader.ReadToEnd();
            return decryptedString;
        }
        public static string TripleDESEncrypt(string plainText)
        {
            //   MemoryStream m = new MemoryStream(Convert.FromBase64String(Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(plainText))));
            //CryptoStream cs = new CryptoStream(m, cp.CreateEncryptor(cp.Key, cp.IV), CryptoStreamMode.Read);
            //cp.Key = Convert.FromBase64String("BeaYzNeHfDb27OFYgaYHUd5HUJE2aZyI");
            //cp.IV = Convert.FromBase64String("T/ENF5G4sCA=");

            //string key = Convert.ToBase64String(cp.Key);
            //string iv = Convert.ToBase64String(cp.IV);

            TripleDESCryptoServiceProvider cp = new TripleDESCryptoServiceProvider();
            MemoryStream m = new MemoryStream(Convert.FromBase64String(Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(plainText))));

            CryptoStream cs = new CryptoStream(m, cp.CreateEncryptor(cp.Key, cp.IV), CryptoStreamMode.Read);

            cp.Key = Convert.FromBase64String("BeaYzNeHfDb27OFYgaYHUd5HUJE2aZyI");
            cp.IV = Convert.FromBase64String("T/ENF5G4sCA=");

            string key = Convert.ToBase64String(cp.Key);
            string iv = Convert.ToBase64String(cp.IV);

            List<byte> r = new List<byte>();
            int x = 0;
            for (; x > -1;)
            {
                x = cs.ReadByte();
                if (x > -1)
                    r.Add((byte)x);
            }
            byte[] y = r.ToArray();
            string cypherText = Convert.ToBase64String(y);
            return cypherText;
        }
        #endregion Not in use


        /// <summary>
        /// Overload method to use only one key
        /// </summary>
        /// <param name="stringToDecrypt"></param>
        /// <returns></returns>
        public static string Decrypt(string stringToDecrypt)
        {
            return Decrypt(stringToDecrypt, CONST_EncryptionKey, false);
        }

        /// <summary>
        /// Encrypt string with one parameter
        /// </summary>
        /// <param name="stringToEncrypt"></param>
        /// <returns></returns>
        public static string Encrypt(string stringToEncrypt)
        {
            return Encrypt(stringToEncrypt, CONST_EncryptionKey, false);
        }






        /// <summary>
        /// Method to decrypt the string
        /// </summary>
        /// <param name="stringToDecrypt"></param>
        /// <param name="sEncryptionKey"></param>
        /// <returns></returns>
        private static string Decrypt(string stringToDecrypt, string sEncryptionKey, bool URLEncode)
        {
            byte[] inputByteArray = new byte[stringToDecrypt.Length + 1];
            try
            {
                key = System.Text.Encoding.UTF8.GetBytes(sEncryptionKey);
                DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                if (URLEncode)
                {
                    inputByteArray = Convert.FromBase64String(HttpUtility.UrlDecode(stringToDecrypt));
                }
                else
                {
                    inputByteArray = Convert.FromBase64String(stringToDecrypt);
                }
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms,
                  des.CreateDecryptor(key, IV), CryptoStreamMode.Write);
                cs.Write(inputByteArray, 0, inputByteArray.Length);
                cs.FlushFinalBlock();
                System.Text.Encoding encoding = System.Text.Encoding.UTF8;
                return encoding.GetString(ms.ToArray());
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }



        /// <summary>
        /// Encrypt the URL 
        /// </summary>
        /// <param name="stringToEncrypt"></param>
        /// <returns></returns>
        public static string EncryptURL(string stringToEncrypt)
        {
            return Encrypt(stringToEncrypt, CONST_EncryptionKey, true);
        }

        public static string DecryptURL(string stringToDecrypt)
        {
            return Decrypt(stringToDecrypt, CONST_EncryptionKey, true);
        }


        /// <summary>
        /// Encrypt the String 
        /// </summary>
        /// <param name="stringToEncrypt"></param>
        /// <param name="SEncryptionKey"></param>
        /// <returns></returns>
        private static string Encrypt(string stringToEncrypt, string SEncryptionKey, bool URLEncode)
        {
            try
            {
                key = System.Text.Encoding.UTF8.GetBytes(SEncryptionKey);
                DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                des.Mode = CipherMode.CBC;
                byte[] inputByteArray = System.Text.Encoding.UTF8.GetBytes(stringToEncrypt);
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(key, IV), CryptoStreamMode.Write);
                cs.Write(inputByteArray, 0, inputByteArray.Length);
                cs.FlushFinalBlock();
                if (URLEncode)
                {
                    return HttpUtility.UrlEncode(Convert.ToBase64String(ms.ToArray()));
                }
                else
                {
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }

        /// <summary>
        ///  Get the value from Query string 
        /// </summary>
        /// <param name="PageRowURL"></param>
        /// <param name="QueryStringKey"></param>
        /// <returns></returns>
        public static string GetQueryStringValue(string PageRowURL, string QueryStringKey)
        {
            string returnValue = "";

            string strReq = "";
            strReq = PageRowURL; // Request.RawUrl;
            strReq = strReq.Substring(strReq.IndexOf('?') + 1);

            if (!strReq.Equals("") && !strReq.Contains(QueryStringKey + "="))
            {
                strReq = DecryptURL(strReq);
            }

            returnValue = HttpUtility.ParseQueryString(strReq).Get(QueryStringKey);

            return returnValue;

        }

        #region  AES Encryption
        public static byte[] AESEncrypt(byte[] clearData, byte[] Key, byte[] IV)
        {
            // Create a MemoryStream to accept the encrypted bytes 
            MemoryStream ms = new MemoryStream();

            // Create a symmetric algorithm. 
            // We are going to use Rijndael because it is strong and
            // available on all platforms. 
            // You can use other algorithms, to do so substitute the
            // next line with something like 
            //      TripleDES alg = TripleDES.Create(); 
            Rijndael alg = Rijndael.Create();

            // Now set the key and the IV. 
            // We need the IV (Initialization Vector) because
            // the algorithm is operating in its default 
            // mode called CBC (Cipher Block Chaining).
            // The IV is XORed with the first block (8 byte) 
            // of the data before it is encrypted, and then each
            // encrypted block is XORed with the 
            // following block of plaintext.
            // This is done to make encryption more secure. 

            // There is also a mode called ECB which does not need an IV,
            // but it is much less secure. 
            alg.Key = Key;
            alg.IV = IV;

            // Create a CryptoStream through which we are going to be
            // pumping our data. 
            // CryptoStreamMode.Write means that we are going to be
            // writing data to the stream and the output will be written
            // in the MemoryStream we have provided. 
            CryptoStream cs = new CryptoStream(ms,
               alg.CreateEncryptor(), CryptoStreamMode.Write);

            // Write the data and make it do the encryption 
            cs.Write(clearData, 0, clearData.Length);

            // Close the crypto stream (or do FlushFinalBlock). 
            // This will tell it that we have done our encryption and
            // there is no more data coming in, 
            // and it is now a good time to apply the padding and
            // finalize the encryption process. 
            cs.Close();

            // Now get the encrypted data from the MemoryStream.
            // Some people make a mistake of using GetBuffer() here,
            // which is not the right way. 
            byte[] encryptedData = ms.ToArray();

            return encryptedData;
        }

        // Encrypt a string into a string using a password 
        //    Uses Encrypt(byte[], byte[], byte[]) 

        /// <summary>
        /// Encrypt clear text.
        /// </summary>
        /// <param name="clearText"></param>
        /// <returns></returns>
        public static string AESEncrypt(string clearText)
        {
            return AESEncrypt(clearText, CONST_EncryptionKey);
        }

        public static string AESEncrypt(string clearText, string Password)
        {
            // First we need to turn the input string into a byte array. 
            byte[] clearBytes =
              System.Text.Encoding.Unicode.GetBytes(clearText);

            // Then, we need to turn the password into Key and IV 
            // We are using salt to make it harder to guess our key
            // using a dictionary attack - 
            // trying to guess a password by enumerating all possible words. 
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d,
            0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});

            // Now get the key/IV and do the encryption using the
            // function that accepts byte arrays. 
            // Using PasswordDeriveBytes object we are first getting
            // 32 bytes for the Key 
            // (the default Rijndael key length is 256bit = 32bytes)
            // and then 16 bytes for the IV. 
            // IV should always be the block size, which is by default
            // 16 bytes (128 bit) for Rijndael. 
            // If you are using DES/TripleDES/RC2 the block size is
            // 8 bytes and so should be the IV size. 
            // You can also read KeySize/BlockSize properties off
            // the algorithm to find out the sizes. 
            byte[] encryptedData = AESEncrypt(clearBytes,
                     pdb.GetBytes(32), pdb.GetBytes(16));

            // Now we need to turn the resulting byte array into a string. 
            // A common mistake would be to use an Encoding class for that.
            //It does not work because not all byte values can be
            // represented by characters. 
            // We are going to be using Base64 encoding that is designed
            //exactly for what we are trying to do. 
            return Convert.ToBase64String(encryptedData);

        }

        // Encrypt bytes into bytes using a password 
        //    Uses Encrypt(byte[], byte[], byte[]) 

        public static byte[] AESEncrypt(byte[] clearData, string Password)
        {
            // We need to turn the password into Key and IV. 
            // We are using salt to make it harder to guess our key
            // using a dictionary attack - 
            // trying to guess a password by enumerating all possible words. 
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d,
            0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});

            // Now get the key/IV and do the encryption using the function
            // that accepts byte arrays. 
            // Using PasswordDeriveBytes object we are first getting
            // 32 bytes for the Key 
            // (the default Rijndael key length is 256bit = 32bytes)
            // and then 16 bytes for the IV. 
            // IV should always be the block size, which is by default
            // 16 bytes (128 bit) for Rijndael. 
            // If you are using DES/TripleDES/RC2 the block size is 8
            // bytes and so should be the IV size. 
            // You can also read KeySize/BlockSize properties off the
            // algorithm to find out the sizes. 
            return AESEncrypt(clearData, pdb.GetBytes(32), pdb.GetBytes(16));

        }

        // Encrypt a file into another file using a password 
        public static void AESEncrypt(string fileIn,
                    string fileOut, string Password)
        {

            // First we are going to open the file streams 
            FileStream fsIn = new FileStream(fileIn,
                FileMode.Open, FileAccess.Read);
            FileStream fsOut = new FileStream(fileOut,
                FileMode.OpenOrCreate, FileAccess.Write);

            // Then we are going to derive a Key and an IV from the
            // Password and create an algorithm 
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d,
            0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});

            Rijndael alg = Rijndael.Create();
            alg.Key = pdb.GetBytes(32);
            alg.IV = pdb.GetBytes(16);

            // Now create a crypto stream through which we are going
            // to be pumping data. 
            // Our fileOut is going to be receiving the encrypted bytes. 
            CryptoStream cs = new CryptoStream(fsOut,
                alg.CreateEncryptor(), CryptoStreamMode.Write);

            // Now will will initialize a buffer and will be processing
            // the input file in chunks. 
            // This is done to avoid reading the whole file (which can
            // be huge) into memory. 
            int bufferLen = 4096;
            byte[] buffer = new byte[bufferLen];
            int bytesRead;

            do
            {
                // read a chunk of data from the input file 
                bytesRead = fsIn.Read(buffer, 0, bufferLen);

                // encrypt it 
                cs.Write(buffer, 0, bytesRead);
            } while (bytesRead != 0);

            // close everything 

            // this will also close the unrelying fsOut stream
            cs.Close();
            fsIn.Close();
        }

        // Decrypt a byte array into a byte array using a key and an IV 
        public static byte[] AESDecrypt(byte[] cipherData,
                                    byte[] Key, byte[] IV)
        {
            // Create a MemoryStream that is going to accept the
            // decrypted bytes 
            MemoryStream ms = new MemoryStream();

            // Create a symmetric algorithm. 
            // We are going to use Rijndael because it is strong and
            // available on all platforms. 
            // You can use other algorithms, to do so substitute the next
            // line with something like 
            //     TripleDES alg = TripleDES.Create(); 
            Rijndael alg = Rijndael.Create();

            // Now set the key and the IV. 
            // We need the IV (Initialization Vector) because the algorithm
            // is operating in its default 
            // mode called CBC (Cipher Block Chaining). The IV is XORed with
            // the first block (8 byte) 
            // of the data after it is decrypted, and then each decrypted
            // block is XORed with the previous 
            // cipher block. This is done to make encryption more secure. 
            // There is also a mode called ECB which does not need an IV,
            // but it is much less secure. 
            alg.Key = Key;
            alg.IV = IV;

            // Create a CryptoStream through which we are going to be
            // pumping our data. 
            // CryptoStreamMode.Write means that we are going to be
            // writing data to the stream 
            // and the output will be written in the MemoryStream
            // we have provided. 
            CryptoStream cs = new CryptoStream(ms,
                alg.CreateDecryptor(), CryptoStreamMode.Write);

            // Write the data and make it do the decryption 
            cs.Write(cipherData, 0, cipherData.Length);

            // Close the crypto stream (or do FlushFinalBlock). 
            // This will tell it that we have done our decryption
            // and there is no more data coming in, 
            // and it is now a good time to remove the padding
            // and finalize the decryption process. 
            cs.Close();

            // Now get the decrypted data from the MemoryStream. 
            // Some people make a mistake of using GetBuffer() here,
            // which is not the right way. 
            byte[] decryptedData = ms.ToArray();

            return decryptedData;
        }

        // Decrypt a string into a string using a password 
        //    Uses Decrypt(byte[], byte[], byte[]) 

        /// <summary>
        ///  AES Descryption
        /// </summary>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static string AESDecrypt(string cipherText)
        {
            return AESDecrypt(cipherText, CONST_EncryptionKey);
        }

        public static string AESDecrypt(string cipherText, string Password)
        {
            // First we need to turn the input string into a byte array. 
            // We presume that Base64 encoding was used 
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            // Then, we need to turn the password into Key and IV 
            // We are using salt to make it harder to guess our key
            // using a dictionary attack - 
            // trying to guess a password by enumerating all possible words. 
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65,
            0x64, 0x76, 0x65, 0x64, 0x65, 0x76});

            // Now get the key/IV and do the decryption using
            // the function that accepts byte arrays. 
            // Using PasswordDeriveBytes object we are first
            // getting 32 bytes for the Key 
            // (the default Rijndael key length is 256bit = 32bytes)
            // and then 16 bytes for the IV. 
            // IV should always be the block size, which is by
            // default 16 bytes (128 bit) for Rijndael. 
            // If you are using DES/TripleDES/RC2 the block size is
            // 8 bytes and so should be the IV size. 
            // You can also read KeySize/BlockSize properties off
            // the algorithm to find out the sizes. 
            byte[] decryptedData = AESDecrypt(cipherBytes,
                pdb.GetBytes(32), pdb.GetBytes(16));

            // Now we need to turn the resulting byte array into a string. 
            // A common mistake would be to use an Encoding class for that.
            // It does not work 
            // because not all byte values can be represented by characters. 
            // We are going to be using Base64 encoding that is 
            // designed exactly for what we are trying to do. 
            return System.Text.Encoding.Unicode.GetString(decryptedData);
        }

        // Decrypt bytes into bytes using a password 
        //    Uses Decrypt(byte[], byte[], byte[]) 

        public static byte[] AESDecrypt(byte[] cipherData, string Password)
        {
            // We need to turn the password into Key and IV. 
            // We are using salt to make it harder to guess our key
            // using a dictionary attack - 
            // trying to guess a password by enumerating all possible words. 
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d,
            0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});

            // Now get the key/IV and do the Decryption using the 
            //function that accepts byte arrays. 
            // Using PasswordDeriveBytes object we are first getting
            // 32 bytes for the Key 
            // (the default Rijndael key length is 256bit = 32bytes)
            // and then 16 bytes for the IV. 
            // IV should always be the block size, which is by default
            // 16 bytes (128 bit) for Rijndael. 
            // If you are using DES/TripleDES/RC2 the block size is
            // 8 bytes and so should be the IV size. 

            // You can also read KeySize/BlockSize properties off the
            // algorithm to find out the sizes. 
            return AESDecrypt(cipherData, pdb.GetBytes(32), pdb.GetBytes(16));
        }

        // Decrypt a file into another file using a password 
        public static void AESDecrypt(string fileIn,
                    string fileOut, string Password)
        {

            // First we are going to open the file streams 
            FileStream fsIn = new FileStream(fileIn,
                        FileMode.Open, FileAccess.Read);
            FileStream fsOut = new FileStream(fileOut,
                        FileMode.OpenOrCreate, FileAccess.Write);

            // Then we are going to derive a Key and an IV from
            // the Password and create an algorithm 
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d,
            0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});
            Rijndael alg = Rijndael.Create();

            alg.Key = pdb.GetBytes(32);
            alg.IV = pdb.GetBytes(16);

            // Now create a crypto stream through which we are going
            // to be pumping data. 
            // Our fileOut is going to be receiving the Decrypted bytes. 
            CryptoStream cs = new CryptoStream(fsOut,
                alg.CreateDecryptor(), CryptoStreamMode.Write);

            // Now will will initialize a buffer and will be 
            // processing the input file in chunks. 
            // This is done to avoid reading the whole file (which can be
            // huge) into memory. 
            int bufferLen = 4096;
            byte[] buffer = new byte[bufferLen];
            int bytesRead;

            do
            {
                // read a chunk of data from the input file 
                bytesRead = fsIn.Read(buffer, 0, bufferLen);

                // Decrypt it 
                cs.Write(buffer, 0, bytesRead);

            } while (bytesRead != 0);

            // close everything 
            cs.Close(); // this will also close the unrelying fsOut stream 
            fsIn.Close();
        }
        #endregion



    }



}

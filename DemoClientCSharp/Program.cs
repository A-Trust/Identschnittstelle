using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Web;
using System.Security.Cryptography.X509Certificates;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography; 

namespace IdentRecordClient
{
    class Program
    {
        static bool bTestSystem = false;
        static bool sign = false;
        static bool encrypt = false;
        static bool upload = false;
        static byte[] EncryptionCertificate = null; 

        static void Main(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11;

            if (args.Length < 2)
            {
                PrintUsage();
                return;
            }


            List<string> filename = new List<string>();

            foreach (string arg in args)
            {
                if (0 == string.Compare(arg, "-test"))
                {
                    bTestSystem = true;
                }
                else if ((0 == string.Compare(arg, "-h", true)) || (0 == string.Compare(arg, "--help", true)))
                {
                    PrintUsage();
                    return;
                }
                else if (0 == string.Compare(arg, "-sign", true))
                {
                    sign = true;
                }
                else if (0 == string.Compare(arg, "-encrypt", true))
                {
                    encrypt = true;
                }
                else if (0 == string.Compare(arg, "-upload", true))
                {
                    upload = true;
                }
                else if (File.Exists(arg))
                {
                    filename.Add(arg);
                }
                else
                {
                    Console.WriteLine("unknown option " + arg + "(ignored)");
                }
            }


            if (!sign && !encrypt && !upload)
            {
                Console.WriteLine("not sign, not upload and not encrypt??");
                Console.WriteLine("");
                PrintUsage();
                Environment.Exit(-1);
                return;
            }

            if (filename.Count <= 0)
            {
                Console.WriteLine("no files specified");
                Console.WriteLine("");
                PrintUsage();
                Environment.Exit(-1);
                return;
            }

            if (encrypt)
            {
                LoadEncryptionCertificate();
            }


            foreach (string file in filename)
            {
                ProcessFile(file);
            }

            Environment.Exit(0);
        }


        private static void ProcessFile(string filename)
        {
            if (sign)
            {
                if (!SignFile(ref filename))
                    return;
            }


            if (encrypt)
            {
                if (!EncryptFile(ref filename))
                    return;
            }

            if (upload)
            {
                if (!UploadFile(filename))
                    return;
            }
            return;
        }

        private static bool LoadEncryptionCertificate()
        {
            string targetUrl = "";
            if (bTestSystem)
            {
                targetUrl = ConfigurationManager.AppSettings["serviceUrlTest"].ToString();
            }
            else
            {
                targetUrl = ConfigurationManager.AppSettings["serviceUrl"].ToString();
            }
            targetUrl += "/Certificate";


            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(targetUrl);
            webRequest.Method = "GET";
            HttpWebResponse webResponse = null;
            byte[] buffer = new byte[4096];
            try
            {
                webResponse = (HttpWebResponse)webRequest.GetResponse();
                Stream responseStream = webResponse.GetResponseStream();

                MemoryStream memoryStream = new MemoryStream();
                int count = 0;
                do
                {
                    count = responseStream.Read(buffer, 0, buffer.Length);
                    memoryStream.Write(buffer, 0, count);

                } while (count != 0);

                EncryptionCertificate = memoryStream.ToArray();
            }
            catch (WebException we)
            {
                Console.WriteLine("error download certificate: " + we.Message);
                Environment.Exit(-1);
                return false;
            }

            return true; 
        }

        #region UploadFile
        private static bool UploadFile(string filename)
        {
            byte[] data = null;
            try
            {
                data = File.ReadAllBytes(filename);
            }
            catch (Exception)
            {
                Console.WriteLine("error loading file to upload");
                Environment.Exit(-1);
                return false;
            }

            if (null == data)
            {
                Console.WriteLine("error loading file to upload (2)");
                Environment.Exit(-1);
                return false;
            }

            string targetUrl = ""; 
            if (bTestSystem)
            {
                targetUrl = ConfigurationManager.AppSettings["serviceUrlTest"].ToString();
            }
            else
            {
                targetUrl = ConfigurationManager.AppSettings["serviceUrl"].ToString();
            }
            targetUrl += "/Identification";

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(targetUrl);
            webRequest.Method = "POST";
            webRequest.ContentLength = data.Length;
            webRequest.GetRequestStream().Write(data, 0, data.Length);
            HttpWebResponse webResponse = null;

            try
            {
                webResponse = (HttpWebResponse)webRequest.GetResponse();
            }
            catch (WebException we)
            {
                Console.WriteLine("error upload file: " + we.Message);
                Environment.Exit(-1);
                return false; 
            }

            if (HttpStatusCode.OK != webResponse.StatusCode)
            {
                Console.WriteLine("error upload file, HTTP Statuscode= " + webResponse.StatusCode.ToString());
                Environment.Exit(-1);
                return false; 
            }

            return true; 
        }
        #endregion

        #region EncryptFile
        private static bool EncryptFile(ref string filename)
        {
            byte[] data = null;
            try
            {
                data = File.ReadAllBytes(filename);
            }
            catch (Exception)
            {
                Console.WriteLine("error loading file to encrypt");
                Environment.Exit(-1);
                return false;
            }

            if (null == data)
            {
                Console.WriteLine("error loading file to encrypt (2)");
                Environment.Exit(-1);
                return false;
            }


            SecureRandom random = new SecureRandom();
            byte[] secretKeyData = new byte[32];
            random.NextBytes(secretKeyData);

            byte[] IV = new byte[16];
            for (int i = 0; i < IV.Length; i++)
                IV[i] = 0x00;

            KeyParameter secretKey = new KeyParameter(secretKeyData);
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            ParametersWithIV aesIVKeyParam = new ParametersWithIV(secretKey, IV);
            cipher.Init(true, aesIVKeyParam);
            MemoryStream bOut = new MemoryStream();
            CipherStream cOut = new CipherStream(bOut, null, cipher);

            cOut.Write(data, 0, data.Length);
            cOut.Close();
            byte[] encryted = bOut.ToArray();


            X509CertificateParser certParser = new X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate cert = certParser.ReadCertificate(EncryptionCertificate);
            AsymmetricKeyParameter pubkey = cert.GetPublicKey();

            //Pkcs1Encoding encryptEngine = new Pkcs1Encoding(new RsaEngine()); // V2 
            OaepEncoding encryptEngine = new OaepEncoding(new RsaEngine()); // V3 
            encryptEngine.Init(true, pubkey);
            byte[] keyblock = encryptEngine.ProcessBlock(secretKeyData, 0, secretKeyData.Length);



            List<byte> ResultBlock = new List<byte>();
            ResultBlock.AddRange(encryted);
            ResultBlock.AddRange(keyblock);

            filename += ".enc";
            File.WriteAllBytes(filename, ResultBlock.ToArray());
            return true;
        }
        #endregion

        #region SignFile
        private static bool SignFile(ref string filename)
        {
            Signing s = new Signing();

            if (!s.LoadFile(filename))
            {
                Console.WriteLine("error loading xml file:" + filename);
                Environment.Exit(-1);
                return false;
            }


            AsymmetricKeyEntry key = null;
            Org.BouncyCastle.X509.X509Certificate cert = null;

            try
            {
                string signercert = ConfigurationManager.AppSettings["signercert"].ToString();
                string signerpwd = ConfigurationManager.AppSettings["signerpwd"].ToString();


                FileStream fs = new FileStream(signercert, FileMode.Open, FileAccess.Read);
                Pkcs12Store store = new Pkcs12Store(fs, signerpwd.ToCharArray());

                string pName = null;
                foreach (string n in store.Aliases)
                {
                    if (store.IsKeyEntry(n))
                    {
                        pName = n;
                        break;
                    }
                }
                key = store.GetKey(pName);
                cert = store.GetCertificate(pName).Certificate;
            }
            catch (Exception)
            {
                Console.WriteLine("error loading signer (config)");
                Environment.Exit(-1);
                return false;
            }

            if ((null == key) || (null == cert))
            {
                Console.WriteLine("error loading signer (config) (2)");
                Environment.Exit(-1);
                return false;
            }


            string signedxml = "";
            try
            {

                byte[] tobesigned = s.AddSignature(cert);

                // sha256WithRSAEncryption
                DerObjectIdentifier signingAlgo = new DerObjectIdentifier("1.2.840.113549.1.1.11");
                ISigner signer = SignerUtilities.GetSigner(signingAlgo);
                signer.Init(true, key.Key);
                signer.BlockUpdate(tobesigned, 0, tobesigned.Length);
                byte[] signed = signer.GenerateSignature();
                s.SetSignature(signed);
                signedxml = s.GetXml();
            }
            catch (Exception)
            {
                Console.WriteLine("error signing xml");
                Environment.Exit(-1);
                return false;
            }

            filename += ".sig";

            File.WriteAllText(filename, signedxml);
            return true;
        }
        #endregion

        #region PrintUsage
        static void PrintUsage()
        {
            string msg = @"IdentRecordClient.exe [options] filepath

Signs and encryptes an identrecord xml for the A-Trust ident-interface.
Appends .sig to filepath for signature and .enc for encryption

-sign               sign identrecord xml with configured key
-encrypt            encrypt identrecord xml 
-upload             upload result file to A-Trust ident serivce
-test               indicates that testsystem encryption key should be used

";
            Console.WriteLine(msg);
        }
        #endregion
    }
}

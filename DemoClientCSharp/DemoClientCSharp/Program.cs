using ATrustIdentRecord;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace IdentRecordClient;

public static class Program
{
    static bool bTestSystem = false;
    static bool sign = false;
    static bool encrypt = false;
    static bool upload = false;
    private static string signercert = "";
    private static string signerpwd = "";
    private static string targetUrl = "";

    static async Task Main(string[] args)
    {
        var configBuilder = new ConfigurationBuilder()
                        .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
                        .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false);
        var config = configBuilder.Build();
        signercert = config.GetValue<string>("signercert") ?? "";
        signerpwd = config.GetValue<string>("signerpwd") ?? "";
        targetUrl = config.GetValue<string>("serviceUrl") ?? "https://hs-abnahme.a-trust.at/aktivierung/v4";


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

        if (bTestSystem)
        {
            targetUrl = config.GetValue<string>("serviceUrlTest") ?? "https://hs-abnahme.a-trust.at/aktivierung/v4";
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

        foreach (string file in filename)
        {
            await ProcessFile(file);
        }

        Environment.Exit(0);
    }


    private static async Task ProcessFile(string filename)
    {
        if (sign)
        {
            var signer = new SoftwareSigner();
            signer.LoadFromFile(signercert, signerpwd);

            var idr = new IdentRecord();
            var result = idr.SignFile(filename, signer);

            if (string.IsNullOrWhiteSpace(result))
            {
                Environment.Exit(-1);
                return;
            }
            filename += ".sig";
            File.WriteAllText(filename, result);
        }

        if (encrypt)
        {
            var cert = await IdentRecordApi.LoadEncryptionCertificate(targetUrl);
            var data = File.ReadAllText(filename);
            var encrypted = IdentRecordEncryption.Encrypt(data, cert);

            if (encrypted is null || encrypted.Length <= 0)
            {
                Environment.Exit(-1);
                return;
            }
            filename += ".enc";
            File.WriteAllBytes(filename, encrypted);
        }


        if (upload)
        {
            var data = File.ReadAllBytes(filename);
            (var result, string? nextUrl) = await IdentRecordApi.Upload(data, targetUrl);

            if (!result)
            {
                Console.WriteLine("error upload file");
                Environment.Exit(-1);
                return;
            }

            if (!string.IsNullOrWhiteSpace(nextUrl))
            {
                Console.WriteLine("next URL: " + nextUrl);
            }
        }
    }

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
}

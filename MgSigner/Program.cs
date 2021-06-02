using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;

using Org.BouncyCastle.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;

using NDesk.Options;

namespace MgSigner
{
    class Program
    {
        static void Main(string[] args)
        {
            bool show_help = false;

            string IN_FILE = null;
            string OUT_FILE = null;
            string CERT_FILE = null;
            string CERT_PWD = null;
            string TSA_SHA = "SHA1";
            string TSA_URL = null;
            string TSA_USR = null;
            string TSA_PWD = null;

            var p = new OptionSet() {
                { "i=|in=", "input PDF file", v => IN_FILE = v },
                { "o=|out=", "output PDF file", v => OUT_FILE = v },
                { "c=|certfile=", "certificate", v => CERT_FILE = v },
                { "p=|certpass=", "certificate password", v => CERT_PWD = v },
                { "tsha=", "timestamp server encrypt algoritm (SHA1, SHA2)", v => TSA_SHA = v },
                { "turl=", "timestamp server url", v => TSA_URL = v },
                { "tusr=", "timestamp server user", v => TSA_USR = v },
                { "tpwd=", "timestamp server password", v => TSA_PWD = v },
                { "h|help",  "show this message and exit", v => show_help = v != null }
            };

            List<string> extra;
            try
            {
                extra = p.Parse(args);
            }
            catch (OptionException e)
            {
                System.Console.Write("MgSigner: ");
                System.Console.WriteLine(e.Message);
                System.Console.WriteLine("Try `MgSigner --help' for more information.");
                return;
            }

            if (IN_FILE == null || OUT_FILE == null || CERT_FILE == null || CERT_PWD == null)
                show_help = true;
            if (!(TSA_SHA == "SHA1" || TSA_SHA == "SHA-256"))
                show_help = true;

            if (show_help)
            {
                ShowHelp(p);
                return;
            }

            System.Console.WriteLine("Sign pdf..");
            
            FileStream fs = new FileStream(CERT_FILE, FileMode.Open);
            Pkcs12Store ks = new Pkcs12Store(fs, CERT_PWD.ToCharArray());
            string alias = null;
            foreach (string al in ks.Aliases)
            {
                if (ks.IsKeyEntry(al) && ks.GetKey(al).Key.IsPrivate)
                {
                    alias = al;
                    break;
                }
            }
            fs.Close();

            ICipherParameters pk = ks.GetKey(alias).Key;
            X509CertificateEntry[] x = ks.GetCertificateChain(alias);
            X509Certificate[] chain = new X509Certificate[x.Length];
            for (int k = 0; k < x.Length; ++k)
            {
                chain[k] = x[k].Certificate;
            }

            PdfReader reader = new PdfReader(IN_FILE);
            FileStream fout = new FileStream(OUT_FILE, FileMode.Create);
            PdfStamper stp = PdfStamper.CreateSignature(reader, fout, '\0');
            PdfSignatureAppearance sap = stp.SignatureAppearance;

            IExternalSignature es = new PrivateKeySignature(pk, "SHA-256");
            ITSAClient tsc = new TSAClientBouncyCastle(TSA_URL, TSA_USR, TSA_PWD, 65535, "SHA-256");

            MakeSignature.SignDetached(sap, es, chain, null, null, tsc, 0, MakeSignature.CMS);

        }

        static void ShowHelp(OptionSet p)
        {
            System.Console.WriteLine("MgSigner v1.1.b2");
            System.Console.WriteLine("Usage: MgSigner [OPTIONS]");
            System.Console.WriteLine();
            System.Console.WriteLine("Options:");
            p.WriteOptionDescriptions(System.Console.Out);
        }

    }
}
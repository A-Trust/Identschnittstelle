using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using System.Collections; 

namespace IdentRecordClient
{
    class Signing
    {
        private XmlDocument m_doc;
        private int m_SignatureId;
        private XmlElement m_XmlDsigSignatureValue;
        private XmlElement m_root;
        private XmlElement XADES_DsigDigestValue;

        private const string XPATH_XADES = "//*[@Id='etsi-signed-1-1']/etsi:QualifyingProperties/etsi:SignedProperties";
        private const string ns_dsig_prefix = "dsig";
        private const string ns_dsig_uri = "http://www.w3.org/2000/09/xmldsig#";
        private const string ns_etsi_uri = "http://uri.etsi.org/01903/v1.1.1#";
        private const string ns_etsi_prefix = "etsi";

        public Signing()
        {
            m_doc = new XmlDocument();
            //m_doc.PreserveWhitespace = true; 
            // this maybe breaks the signature
            m_root = null;
            m_XmlDsigSignatureValue = null; 
            XADES_DsigDigestValue = null; 
        }


        public bool LoadFile(string filename)
        {
            try
            {
                m_doc.Load(filename);
            }
            catch(Exception)
            {
                return false; 
            }


            m_root = m_doc.DocumentElement;

            return true; 
        }


        #region AddSignature
        public byte[] AddSignature(Org.BouncyCastle.X509.X509Certificate cert)
        {
            m_XmlDsigSignatureValue = null;
            m_SignatureId = m_SignatureId + 1;
            byte[] toBehashed = DoC14N(m_doc);

            HashAlgorithm hash = new SHA256Managed();
            byte[] TheHash = hash.ComputeHash(toBehashed);
            byte[] toBeSigned = CreateSignatureElemente(Convert.ToBase64String(TheHash, Base64FormattingOptions.InsertLineBreaks), cert);
            return toBeSigned;
        }
        #endregion

        #region SetSignature
        public void SetSignature(byte[] signature)
        {
            string SigB64 = Convert.ToBase64String(signature, Base64FormattingOptions.InsertLineBreaks);
            SigB64 = SigB64.Replace("\r\n", "\n");

            m_XmlDsigSignatureValue.AppendChild(m_doc.CreateTextNode(SigB64));
            m_XmlDsigSignatureValue = null;
        }
        #endregion 

        #region GetXml
        public string GetXml()
        {
            return m_doc.OuterXml;
        }
        #endregion 

        #region c14n
        private byte[] DoC14N(XmlDocument doc)
        {
            XmlDsigC14NTransform c14n = new XmlDsigC14NTransform(false);
            c14n.LoadInput(doc);
            return DoC14N(c14n);
        }

        private byte[] DoC14N(XmlDocument doc, string xpath)
        {
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace(ns_etsi_prefix, ns_etsi_uri);
            XmlNodeList c14nNodes = doc.SelectNodes(xpath, nsmgr);            
            XmlDsigC14NTransform c14n = new XmlDsigC14NTransform(false);
            //Type[] inputtypes = c14n.InputTypes;
            c14n.LoadInput(c14nNodes);
            return DoC14N(c14n);
        }

        private byte[] DoC14N_Xades(XmlDocument doc)
        {
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace(ns_etsi_prefix, ns_etsi_uri);
            XmlNode node1 = doc.SelectSingleNode(XPATH_XADES, nsmgr);

            XmlNodeList list = node1.SelectNodes("descendant-or-self::node()|//@*");
            XmlDsigC14NTransform c14n = new XmlDsigC14NTransform(false);
            c14n.LoadInput(list);
            return DoC14N(c14n);
        }

        private byte[] DoC14N(XmlDsigC14NTransform c14n)
        {
            byte[] toBeSigned = null;
            try
            {
                Stream s1 = (Stream)c14n.GetOutput();
                long len = s1.Length;
                toBeSigned = new byte[len];
                s1.Read(toBeSigned, 0, (int)len);
            }
            catch (Exception)
            {
                return null; 
            }
            return toBeSigned;
        }
        #endregion 

        #region SignatureElement
        private byte[] CreateSignatureElemente(string TheHash, Org.BouncyCastle.X509.X509Certificate cert)
        {
            string sCert = Convert.ToBase64String(cert.GetEncoded());
            sCert = sCert.Replace("\r\n", "\n");

            XmlElement XmlDsigSignature = m_doc.CreateElement(ns_dsig_prefix, "Signature", ns_dsig_uri);
            XmlDsigSignature.SetAttribute("Id", "signature-" + m_SignatureId.ToString());

            XmlElement XmlDsigSignedInfo = m_doc.CreateElement(ns_dsig_prefix, "SignedInfo", ns_dsig_uri);
            XmlDsigSignedInfo.SetAttribute("Id", "signedinfo-" + m_SignatureId.ToString());
            XmlDsigSignature.AppendChild(XmlDsigSignedInfo);

            XmlElement XmlDsigCanonicalizationMethod = m_doc.CreateElement(ns_dsig_prefix, "CanonicalizationMethod", ns_dsig_uri);
            XmlDsigSignedInfo.AppendChild(XmlDsigCanonicalizationMethod);
            XmlAttribute algo1 = m_doc.CreateAttribute("Algorithm");
            algo1.Value = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
            XmlDsigCanonicalizationMethod.Attributes.Append(algo1);

            XmlElement XmlDsigSignatureMethod = m_doc.CreateElement(ns_dsig_prefix, "SignatureMethod", ns_dsig_uri);
            XmlDsigSignedInfo.AppendChild(XmlDsigSignatureMethod);
            XmlAttribute algo2 = m_doc.CreateAttribute("Algorithm");
            algo2.Value = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            XmlDsigSignatureMethod.Attributes.Append(algo2);

            AddReferenceDoc(TheHash, XmlDsigSignedInfo);
            AddReferenceXades(XmlDsigSignedInfo);

            m_root.AppendChild(XmlDsigSignature);

            m_XmlDsigSignatureValue = m_doc.CreateElement(ns_dsig_prefix, "SignatureValue", ns_dsig_uri);
            XmlDsigSignature.AppendChild(m_XmlDsigSignatureValue);
            //set value after signing
            // x509
            XmlElement XmlDsigKeyInfo = m_doc.CreateElement(ns_dsig_prefix, "KeyInfo", ns_dsig_uri);
            XmlDsigSignature.AppendChild(XmlDsigKeyInfo);

            XmlElement XmlDsigX509Data = m_doc.CreateElement(ns_dsig_prefix, "X509Data", ns_dsig_uri);
            XmlDsigKeyInfo.AppendChild(XmlDsigX509Data);

            XmlElement XmlDsigX509Certificate = m_doc.CreateElement(ns_dsig_prefix, "X509Certificate", ns_dsig_uri);
            XmlDsigX509Data.AppendChild(XmlDsigX509Certificate);
            XmlDsigX509Certificate.AppendChild(m_doc.CreateTextNode(sCert));

            XmlElement ele = CreateXadesObject(cert);
            XmlDsigSignature.AppendChild(ele);

            byte[] tohash = DoC14N_Xades(m_doc);
            //string xml = System.Text.Encoding.UTF8.GetString(tohash); 
            HashAlgorithm hash = new SHA256Managed();
            byte[] TheHash2 = hash.ComputeHash(tohash);
            XADES_DsigDigestValue.AppendChild(m_doc.CreateTextNode(Convert.ToBase64String(TheHash2))); 

            byte[] toBeSigned = DoC14N(m_doc, "//*[@Id='signedinfo-" + m_SignatureId.ToString() + "'] /descendant-or-self::node()|//*[@Id='signedinfo-" + m_SignatureId.ToString() + "']//@*");
            //string xml = System.Text.Encoding.UTF8.GetString(toBeSigned); 
            return toBeSigned;
        }
        #endregion 

        #region CreateXadesObject
        private XmlElement CreateXadesObject(Org.BouncyCastle.X509.X509Certificate cert)
        {
            X509Name old = cert.SubjectDN;
            X509Name n = new X509Name(old.GetOidList(), old.GetValueList());
            byte[] data = n.GetDerEncoded(); 
            Sha1Digest hash = new Sha1Digest();
            hash.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[hash.GetDigestSize()];
            hash.DoFinal(result, 0);
            string sCertDigest = Convert.ToBase64String(result);

            string Issuer = cert.IssuerDN.ToString(true, X509Name.RFC2253Symbols);
            string Serial = cert.SerialNumber.LongValue.ToString(); 


            XmlElement XmlObject = m_doc.CreateElement(ns_dsig_prefix, "Object", ns_dsig_uri);
            XmlAttribute Id = m_doc.CreateAttribute("Id");
            Id.Value = "etsi-signed-1-1";
            XmlObject.Attributes.Append(Id);

            XmlElement QualifyingProperties = m_doc.CreateElement(ns_etsi_prefix, "QualifyingProperties", ns_etsi_uri);
            XmlObject.AppendChild(QualifyingProperties);
            XmlAttribute Target = m_doc.CreateAttribute("Target");
            Target.Value = "#signature-1-1";
            QualifyingProperties.Attributes.Append(Target);
            XmlAttribute nsxml = m_doc.CreateAttribute("xmlns:" + ns_etsi_prefix);
            nsxml.Value = ns_etsi_uri;
            QualifyingProperties.Attributes.Append(nsxml);

            XmlElement SignedProperties = m_doc.CreateElement(ns_etsi_prefix, "SignedProperties", ns_etsi_uri);
            QualifyingProperties.AppendChild(SignedProperties);

            XmlElement SignedSignatureProperties = m_doc.CreateElement(ns_etsi_prefix, "SignedSignatureProperties", ns_etsi_uri);
            SignedProperties.AppendChild(SignedSignatureProperties);

            XmlElement SigningTime = m_doc.CreateElement(ns_etsi_prefix, "SigningTime", ns_etsi_uri);
            SignedSignatureProperties.AppendChild(SigningTime);
            SigningTime.AppendChild(m_doc.CreateTextNode(DateTime.UtcNow.ToString("s") + "Z"));

            XmlElement SigningCertificate = m_doc.CreateElement(ns_etsi_prefix, "SigningCertificate", ns_etsi_uri);
            SignedSignatureProperties.AppendChild(SigningCertificate);
            XmlElement Cert = m_doc.CreateElement(ns_etsi_prefix, "Cert", ns_etsi_uri);
            SigningCertificate.AppendChild(Cert);

            XmlElement CertDigest = m_doc.CreateElement(ns_etsi_prefix, "CertDigest", ns_etsi_uri);
            Cert.AppendChild(CertDigest);
            XmlElement DigestMethod = m_doc.CreateElement(ns_etsi_prefix, "DigestMethod", ns_etsi_uri);
            CertDigest.AppendChild(DigestMethod);
            XmlAttribute Algorithm = m_doc.CreateAttribute("Algorithm");
            Algorithm.Value = "http://www.w3.org/2000/09/xmldsig#sha1";
            DigestMethod.Attributes.Append(Algorithm);
            XmlElement DigestValue = m_doc.CreateElement(ns_etsi_prefix, "DigestValue", ns_etsi_uri);
            CertDigest.AppendChild(DigestValue);
            DigestValue.AppendChild(m_doc.CreateTextNode(sCertDigest));


            XmlElement IssuerSerial = m_doc.CreateElement(ns_etsi_prefix, "IssuerSerial", ns_etsi_uri);
            Cert.AppendChild(IssuerSerial);
            XmlElement X509IssuerName = m_doc.CreateElement(ns_dsig_prefix, "X509IssuerName", ns_dsig_uri);
            IssuerSerial.AppendChild(X509IssuerName);
            X509IssuerName.AppendChild(m_doc.CreateTextNode(Issuer));
            XmlElement X509SerialNumber = m_doc.CreateElement(ns_dsig_prefix, "X509SerialNumber", ns_dsig_uri);
            IssuerSerial.AppendChild(X509SerialNumber);
            X509SerialNumber.AppendChild(m_doc.CreateTextNode(Serial));


            XmlElement SignaturePolicyIdentifier = m_doc.CreateElement(ns_etsi_prefix, "SignaturePolicyIdentifier", ns_etsi_uri);
            SignedSignatureProperties.AppendChild(SignaturePolicyIdentifier);
            XmlElement SignaturePolicyImplied = m_doc.CreateElement(ns_etsi_prefix, "SignaturePolicyImplied", ns_etsi_uri);
            SignaturePolicyIdentifier.AppendChild(SignaturePolicyImplied);

            XmlElement SignedDataObjectProperties = m_doc.CreateElement(ns_etsi_prefix, "SignedDataObjectProperties", ns_etsi_uri);
            SignedProperties.AppendChild(SignedDataObjectProperties);
            XmlElement DataObjectFormat = m_doc.CreateElement(ns_etsi_prefix, "DataObjectFormat", ns_etsi_uri);
            SignedDataObjectProperties.AppendChild(DataObjectFormat);
            XmlAttribute ObjectReference = m_doc.CreateAttribute("ObjectReference");
            ObjectReference.Value = "#reference-1-1";
            DataObjectFormat.Attributes.Append(ObjectReference);

            XmlElement MimeType = m_doc.CreateElement(ns_etsi_prefix, "MimeType", ns_etsi_uri);
            DataObjectFormat.AppendChild(MimeType);
            MimeType.AppendChild(m_doc.CreateTextNode("text/xml"));

            return XmlObject; 
        }
        #endregion 

        #region AddReferenceXades
        private void AddReferenceXades(XmlElement XmlDsigSignedInfo)
        {
            XmlElement XmlDsigReference = m_doc.CreateElement(ns_dsig_prefix, "Reference", ns_dsig_uri);
            XmlDsigSignedInfo.AppendChild(XmlDsigReference);
            XmlAttribute uri = m_doc.CreateAttribute("URI");
            uri.Value = "";
            XmlDsigReference.Attributes.Append(uri);
            XmlAttribute Id = m_doc.CreateAttribute("Id");
            Id.Value = "etsi-data-reference-1-1";
            XmlDsigReference.Attributes.Append(Id);
            XmlAttribute Type = m_doc.CreateAttribute("Type");
            Type.Value = "http://uri.etsi.org/01903/v1.1.1#SignedProperties";
            XmlDsigReference.Attributes.Append(Type);


            // reference
            XmlElement XmlDsigTransforms = m_doc.CreateElement(ns_dsig_prefix, "Transforms", ns_dsig_uri);
            XmlDsigReference.AppendChild(XmlDsigTransforms);

            XmlElement XmlDsigTransform1 = m_doc.CreateElement(ns_dsig_prefix, "Transform", ns_dsig_uri);
            XmlDsigTransforms.AppendChild(XmlDsigTransform1);
            XmlAttribute algo3 = m_doc.CreateAttribute("Algorithm");
            algo3.Value = "http://www.w3.org/2002/06/xmldsig-filter2";
            XmlDsigTransform1.Attributes.Append(algo3);

            string ns_xpf = "http://www.w3.org/2002/06/xmldsig-filter2";
            string ns_xpf_prefix = "xpf";
            XmlElement xpath = m_doc.CreateElement(ns_xpf_prefix, "XPath", ns_xpf);
            XmlDsigTransform1.AppendChild(xpath);
            xpath.AppendChild(m_doc.CreateTextNode(XPATH_XADES));
            XmlAttribute Filter = m_doc.CreateAttribute("Filter");
            Filter.Value = "intersect";
            xpath.Attributes.Append(Filter);
            XmlAttribute xmlns_etsi = m_doc.CreateAttribute("xmlns:etsi");
            xmlns_etsi.Value = "http://uri.etsi.org/01903/v1.1.1#";
            xpath.Attributes.Append(xmlns_etsi);
            XmlAttribute xmlns_xpf = m_doc.CreateAttribute("xmlns:" + ns_xpf_prefix);
            xmlns_xpf.Value = "http://www.w3.org/2002/06/xmldsig-filter2";
            xpath.Attributes.Append(xmlns_xpf);



            XmlElement XmlDsigDigestMethod = m_doc.CreateElement(ns_dsig_prefix, "DigestMethod", ns_dsig_uri);
            XmlDsigReference.AppendChild(XmlDsigDigestMethod);
            XmlAttribute algo5 = m_doc.CreateAttribute("Algorithm");
            algo5.Value = "http://www.w3.org/2001/04/xmlenc#sha256";
            XmlDsigDigestMethod.Attributes.Append(algo5);

            XADES_DsigDigestValue = m_doc.CreateElement(ns_dsig_prefix, "DigestValue", ns_dsig_uri);
            XmlDsigReference.AppendChild(XADES_DsigDigestValue);
        }
        #endregion 

        #region AddReferenceDoc
        private void AddReferenceDoc(string TheHash, XmlElement XmlDsigSignedInfo)
        {
            XmlElement XmlDsigReference = m_doc.CreateElement(ns_dsig_prefix, "Reference", ns_dsig_uri);
            XmlDsigSignedInfo.AppendChild(XmlDsigReference);
            XmlAttribute uri = m_doc.CreateAttribute("URI");
            uri.Value = "";
            XmlDsigReference.Attributes.Append(uri);

            // reference
            XmlElement XmlDsigTransforms = m_doc.CreateElement(ns_dsig_prefix, "Transforms", ns_dsig_uri);
            XmlDsigReference.AppendChild(XmlDsigTransforms);

            XmlElement XmlDsigTransform1 = m_doc.CreateElement(ns_dsig_prefix, "Transform", ns_dsig_uri);
            XmlDsigTransforms.AppendChild(XmlDsigTransform1);
            XmlAttribute algo3 = m_doc.CreateAttribute("Algorithm");
            algo3.Value = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
            XmlDsigTransform1.Attributes.Append(algo3);

            XmlElement XmlDsigTransform2 = m_doc.CreateElement(ns_dsig_prefix, "Transform", ns_dsig_uri);
            XmlDsigTransforms.AppendChild(XmlDsigTransform2);
            XmlAttribute algo4 = m_doc.CreateAttribute("Algorithm");
            algo4.Value = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
            XmlDsigTransform2.Attributes.Append(algo4);

            XmlElement XmlDsigDigestMethod = m_doc.CreateElement(ns_dsig_prefix, "DigestMethod", ns_dsig_uri);
            XmlDsigReference.AppendChild(XmlDsigDigestMethod);
            XmlAttribute algo5 = m_doc.CreateAttribute("Algorithm");
            algo5.Value = "http://www.w3.org/2001/04/xmlenc#sha256";
            XmlDsigDigestMethod.Attributes.Append(algo5);

            XmlElement XmlDsigDigestValue = m_doc.CreateElement(ns_dsig_prefix, "DigestValue", ns_dsig_uri);
            XmlDsigReference.AppendChild(XmlDsigDigestValue);
            XmlDsigDigestValue.AppendChild(m_doc.CreateTextNode(TheHash));
        }
        #endregion 
    }
}

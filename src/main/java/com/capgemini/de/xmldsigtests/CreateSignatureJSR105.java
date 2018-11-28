/**
 * This is a simple example of generating an Enveloped XML
 * Signature using the JSR 105 API. The resulting signature will look
 * like (key and signature values will be different):
 *
 * <pre><code>
 *<Envelope xmlns="urn:envelope">
 * <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
 *   <SignedInfo>
 *     <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
 *     <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
 *     <Reference URI="">
 *       <Transforms>
 *         <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
 *          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
 *       </Transforms>
 *       <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *       <DigestValue>K8M/lPbKnuMDsO0Uzuj75lQtzQI=<DigestValue>
 *     </Reference>
 *   </SignedInfo>
 *   <SignatureValue>
 *     DpEylhQoiUKBoKWmYfajXO7LZxiDYgVtUtCNyTgwZgoChzorA2nhkQ==
 *   </SignatureValue>
 *   <KeyInfo>
 *     <KeyValue>
 *       <RSAKeyValue>
 *        <Modulus>ygPSo3j0GR6U4obxWT82fBsIgZevUDlsS37oDvaxRY3dn5lqvgCQw8IUP2BcUdV9j6bglymBfkR9
72FjgMHdi+mNxQaP2emOxNRb+HiiToLCPbjZWiRrgVOZedlDrAXIJeBFaPRA0ZaeReNJk3h2qDEZ
3JBcNa2hDVr6i3VJc8NPVCM9yn6tVPxRISSZRYORIdul7uJB20aAeQG8pWwFtpTv2dxjxgKc7XpY
QCh+fb/or8ovMCOU6QHJ0WeeYNNvN7oPOpzr5N7aEK6/oiKd1cqTs4onArd0eEvG+Z0LfeUhE+BO
N+lhE7x6wrvM49/lcMWoopMJcqq07MyGYNbC6Q==</Modulus>
 *         <Exponent>AQAB</Exponent>
 *       </RSAKeyValue>
 *     </KeyValue>
 *   </KeyInfo>
 * </Signature>
 *</Envelope>
 * </code></pre>
 */

package com.capgemini.de.xmldsigtests;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class CreateSignatureJSR105 {

    //
    // Synopsis: java CreateSignatureJSR105  [document] [output]
    //
    //    where "document" is the name of a file containing the XML document
    //    to be signed, and "output" is the name of the file to store the
    //    signed document. The 2nd argument is optional - if not specified,
    //    standard output will be used.
    //
    public static void main(String[] args) throws Exception {

        //All the parameters for the keystore
        String keystoreType     = "JKS";
        String keystoreFile     = "build/envelope.keystore";
        String keystorePass     = "my-password";
        String privateKeyAlias  = "envelope";
        String privateKeyPass   = "my-password";
        String certificateAlias = "envelope";

        KeyStore ks = KeyStore.getInstance(keystoreType);
        FileInputStream fis = new FileInputStream(keystoreFile);
        
        //load the keystore
        ks.load(fis, keystorePass.toCharArray());

        //get the private key for signing
        PrivateKey privateKey = (PrivateKey) ks.getKey(privateKeyAlias, privateKeyPass.toCharArray());

        PublicKey publicKey = ks.getCertificate(certificateAlias).getPublicKey();
        KeyPair kp = new KeyPair(publicKey, privateKey);

        // Instantiate the document to be signed
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new FileInputStream(args[0]));

        Element root = doc.getDocumentElement();

        // Create a DOM XMLSignatureFactory that will be used to generate the enveloped signature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Use RSA-256 as algorithm for digital signature
        SignatureMethod signatureMethod = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);

        // Create the list of transformations for the Document/Reference
        final List<Transform> transforms = new ArrayList<Transform>(2);
        transforms.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
        transforms.add(fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null));

        Reference ref = fac.newReference
            ("", fac.newDigestMethod(DigestMethod.SHA256, null),
             transforms,
             null, null);

        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo
            (fac.newCanonicalizationMethod
             (CanonicalizationMethod.EXCLUSIVE,
              (C14NMethodParameterSpec) null),
             signatureMethod,
             Collections.singletonList(ref));

        // Remove any old Signature node
        NodeList nodes = doc.getElementsByTagName("Signature");
        for (int i = 0; i < nodes.getLength(); i++) {
          Node signaturinfonode = nodes.item(i);
          signaturinfonode.getParentNode().removeChild(signaturinfonode);
        }

        // Create a KeyValue containing the RSA PublicKey
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());
        // Create a KeyInfo and add the KeyValue to it
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = fac.newXMLSignature(si, ki);

        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element
        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), root);
        // sign the enveloped signature
        signature.sign(dsc);

        // output the resulting document
        OutputStream os;
        if (args.length > 1) {
           os = new FileOutputStream(args[1]);
        } else {
           os = System.out;
        }

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));

        os.close();

    }
}

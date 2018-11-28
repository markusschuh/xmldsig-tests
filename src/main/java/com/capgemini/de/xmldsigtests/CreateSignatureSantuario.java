/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.capgemini.de.xmldsigtests;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.xml.parsers.DocumentBuilder;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class CreateSignatureSantuario {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(CreateSignatureSantuario.class);

    //
    // Synopsis: java CreateSignatureSantuario [document] [output]
    //
    //    where "document" is the name of a file containing the XML document
    //    to be signed, and "output" is the name of the file to store the
    //    signed document. The 2nd argument is optional - if not specified,
    //    standard output will be used.
    //
    public static void main(String[] args) throws Exception {

        org.apache.xml.security.Init.init();
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");

        //All the parameters for the keystore
        String keystoreType     = "JKS";
        String keystoreFile     = "src/test/resources/envelope.keystore";
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
        DocumentBuilder db = XMLUtils.createDocumentBuilder(false);
        Document doc = db.parse(new FileInputStream(args[0]));

        Element root = doc.getDocumentElement();

        // Use RSA-256 as algorithm for digital signature
        SignatureAlgorithm signatureAlgorithm =
          new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);

        // Create the list of transformations for the Document/Reference
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        Element canonElem =
            XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
            null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        );

        // Create a XMLSignature that will be used to generate the enveloped signature
        XMLSignature signature =
          new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);

        //Add the above Document/Reference
        signature.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

        // Remove any old Signature node
        NodeList nodes = doc.getElementsByTagName("Signature");
        for (int i = 0; i < nodes.getLength(); i++) {
          Element signaturinfonode = (Element)nodes.item(i);
          signaturinfonode.getParentNode().removeChild(signaturinfonode);
        }

        signature.addKeyInfo(kp.getPublic());

        root.appendChild(signature.getElement());
        // sign the enveloped signature
        signature.sign(kp.getPrivate());

        // output the resulting document
        OutputStream os;
        if (args.length > 1) {
           os = new FileOutputStream(args[1]);
        } else {
           os = System.out;
        }

        XMLUtils.outputDOM(doc, os);

        os.close();

    }
}

/* $Id: RSASignature_PKCS1_SHA1.java,v 1.2 2000/01/20 14:59:33 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


/**
 * A class to digest a message with SHA-1, and sign/verify the
 * resulting hash using the RSA digital signature scheme, with PKCS#1
 * block padding.
 *
 * @version $Revision: 1.2 $
 * @author  Raif S. Naffah
 * @author  David Hopwood
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class RSASignature_PKCS1_SHA1
extends RSASignature_PKCS1
{
// Constants and variables
//...........................................................................

    private static final byte[] SHA1_ASN_DATA = 
    {
        0x30, 0x21,                                // SEQUENCE 33
          0x30, 0x09,                                // SEQUENCE 9
            0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A,  // OID {1.3.14.3.2.26}
            0x05, 0x00,                                // NULL
          0x04, 0x14                                 // OCTET STRING 20
    };


// Constructor
//...........................................................................

    public RSASignature_PKCS1_SHA1 () 
    { 
        super("SHA-1"); 
    }


// RSASignature_PKCS1 abstract method implementation
//...........................................................................

    protected byte[] getAlgorithmEncoding () 
    { 
        return SHA1_ASN_DATA; 
    }
}

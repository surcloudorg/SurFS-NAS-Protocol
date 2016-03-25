/* $Id: RSASignature_PKCS1_SHA256.java,v 1.1 2001/05/18 03:03:51 gelderen Exp $
 *
 * Copyright (C) 2001 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


/**
 * A class to digest a message with SHA256, and sign/verify the
 * resulting hash using the RSA digital signature scheme, with PKCS#1
 * block padding.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen
 */
public class RSASignature_PKCS1_SHA256 extends RSASignature_PKCS1 {

// Constants and variables
//...........................................................................

    private static final byte[] SHA256_ASN_DATA = {
        /* Taken from PKCS#1 1v2-1d1. */
        0x30, 0x31,                                    // SEQUENCE 49
          0x30, 0x0d,                                    // SEQUENCE 13
            0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,      // OID
                        0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00,                                    // NULL
          0x04, 0x20                                     // OCTET STRING 32
    };


// Constructor
//...........................................................................

    public RSASignature_PKCS1_SHA256() { super("SHA-256"); }


// RSASignature_PKCS1 abstract method implementation
//...........................................................................

    protected byte[] getAlgorithmEncoding() { return SHA256_ASN_DATA; }
}

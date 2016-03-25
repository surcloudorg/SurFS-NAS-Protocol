/* $Id: RSASignature_PKCS1_RIPEMD160.java,v 1.2 2000/01/20 14:59:33 gelderen Exp $
 *
 * Copyright (C) 1995-1999 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


/**
 * A class to digest a message with RIPEMD160, and sign/verify the
 * resulting hash using the RSA digital signature scheme, with PKCS#1
 * block padding.
 *
 * @version $Revision: 1.2 $
 * @author  Raif S. Naffah
 * @author  David Hopwood
 * @author  Jeroen C. van Gelderen
 * @since   Cryptix 2.2.2
 */
public class RSASignature_PKCS1_RIPEMD160
extends RSASignature_PKCS1
{
// Constants and variables
//...........................................................................

    private static final byte[] RIPEMD160_ASN_DATA = 
    {
        0x30, 0x21,                                    // SEQUENCE 33
          0x30, 0x09,                                    // SEQUENCE 9
            0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01,      // OID {1.3.36.3.2.1}
            0x05, 0x00,                                    // NULL
          0x04, 0x14                                     // OCTET STRING 20
    };


// Constructor
//...........................................................................

    public RSASignature_PKCS1_RIPEMD160() { super("RIPEMD160"); }


// RSASignature_PKCS1 abstract method implementation
//...........................................................................

    protected byte[] getAlgorithmEncoding() { return RIPEMD160_ASN_DATA; }
}

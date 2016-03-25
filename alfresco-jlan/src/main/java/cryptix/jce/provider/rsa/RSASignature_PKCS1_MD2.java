/* $Id: RSASignature_PKCS1_MD2.java,v 1.2 2000/01/20 14:59:33 gelderen Exp $
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
 * A class to digest a message with MD2, and sign/verify the
 * resulting hash using the RSA digital signature scheme, with PKCS#1
 * block padding.
 *
 * @version $Revision: 1.2 $
 * @author  Raif S. Naffah
 * @author  David Hopwood
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class RSASignature_PKCS1_MD2
extends RSASignature_PKCS1
{
    
// Constants and variables
//...........................................................................

    private static final byte[] MD2_ASN_DATA = 
    {
        0x30, 0x20,                             // SEQUENCE 32
         0x30, 0x0C,                            // SEQUENCE 12
          0x06, 0x08, 0x2A, (byte)0x86, 0x48,   // OID md2 {1.2.840.113549.2.2}
          (byte)0x86, (byte)0xF7, 0x0D, 0x02, 0x02,
          0x05, 0x00,                           // NULL
         0x04, 0x10                             // OCTET STRING 16
    };


// Constructor
//...........................................................................

    public RSASignature_PKCS1_MD2 () 
    { 
        super("MD2"); 
    }


// RSASignature_PKCS1 abstract method implementation
//...........................................................................

    protected byte[] getAlgorithmEncoding () 
    { 
        return MD2_ASN_DATA; 
    }
}

/* $Id: RSAPublicKeyX509.java,v 1.3 2001/07/10 18:54:37 edwin Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


import cryptix.jce.provider.asn.AsnBitString;
import cryptix.jce.provider.asn.AsnInteger;
import cryptix.jce.provider.asn.AsnObject;
import cryptix.jce.provider.asn.AsnObjectId;
import cryptix.jce.provider.asn.AsnOutputStream;
import cryptix.jce.provider.asn.AsnSequence;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;


/**
 * @version $Revision: 1.3 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
/*package*/ final class RSAPublicKeyX509
implements RSAPublicKey
{
    private final BigInteger n, e;


    /*package*/ RSAPublicKeyX509(BigInteger n, BigInteger e)
    {
        this.n = n;
        this.e = e;
    }


    public BigInteger getModulus()
    {
        return this.n;
    }


    public BigInteger getPublicExponent()
    {
        return this.e;
    }


// Implementation of Key interface
//...........................................................................

    public String getAlgorithm()
    {
        return "RSA";
    }


    public String getFormat()
    {
        return "X.509";
    }


    public byte[] getEncoded()
    {
        /*
         * SubjectPublicKeyInfo ::= SEQUENCE {
         *     algorithm AlgorithmIdentifier,
         *     subjectPublicKey BIT STRING
         * }
         *
         * AlgorithmIdentifier ::= SEQUENCE {
         *     algorithm OBJECT IDENTIFIER,
         *     parameters ANY DEFINED BY algorithm OPTIONAL
         * }
         *
         * PKCS#1 defines;
         *
         * rsaEncryption OBJECT IDENTIFIER ::=  { 1 2 840 113549 1 1 1 }
         *
         * RSAPublicKey ::= SEQUENCE {
         *  modulus INTEGER, -- n
         *  publicExponent INTEGER -- e
         * }
         */

        AsnObject[] spkData = { new AsnInteger(this.n),new AsnInteger(this.e) };
		byte[] spkBytes;
		
		try
		{
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            AsnOutputStream       dos  = new AsnOutputStream(baos);
            dos.write( new AsnSequence(spkData) );
            dos.flush();
            dos.close();
            spkBytes = baos.toByteArray();
		}		
        catch(IOException e)
        {
            throw new RuntimeException("PANIC");
        }
		
        AsnBitString subjectPublicKey = new AsnBitString( spkBytes );

        AsnObject[] algData = { AsnObjectId.OID_rsaEncryption };
        AsnSequence algorithm = new AsnSequence(algData);

        AsnObject[] spkiData = { algorithm, subjectPublicKey };
        AsnSequence subjectPublicKeyInfo = new AsnSequence( spkiData );

        try
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            AsnOutputStream       dos  = new AsnOutputStream(baos);
            dos.write(subjectPublicKeyInfo);
            dos.flush();
            dos.close();
            return baos.toByteArray();
        }
        catch(IOException e)
        {
            throw new RuntimeException("PANIC");
        }
    }
}

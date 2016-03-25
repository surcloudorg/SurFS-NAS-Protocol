/* $Id: RSAPublicKeyCryptix.java,v 1.3 2000/08/25 01:23:06 gelderen Exp $
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


import cryptix.jce.util.MPIOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;


/**
 * @version $Revision: 1.3 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class RSAPublicKeyCryptix
implements RSAPublicKey
{
    private final BigInteger n, e;


    public RSAPublicKeyCryptix(BigInteger n, BigInteger e)
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
        return "Cryptix";
    }


    public byte[] getEncoded()
    {
        try
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            MPIOutputStream       mos  = new MPIOutputStream(baos);
            mos.write(this.n);
            mos.write(this.e);
            mos.flush();
            mos.close();
            return baos.toByteArray();
        }
        catch(IOException e)
        {
            throw new RuntimeException("PANIC");
        }
    }
}

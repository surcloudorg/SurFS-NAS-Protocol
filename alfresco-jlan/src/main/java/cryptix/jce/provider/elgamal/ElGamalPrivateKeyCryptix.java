/* $Id: ElGamalPrivateKeyCryptix.java,v 1.2 2000/01/20 14:59:28 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.elgamal;


import cryptix.jce.ElGamalParams;
import cryptix.jce.ElGamalPrivateKey;
import cryptix.jce.util.MPIOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;


/**
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
/*package*/ final class ElGamalPrivateKeyCryptix
implements ElGamalPrivateKey
{

// Instance variables
//...........................................................................

    private final BigInteger x;
    private final ElGamalParams params;
    

// Constructor
//...........................................................................

    /*package*/ ElGamalPrivateKeyCryptix(BigInteger x, ElGamalParams params)
    {
        this.x      = x;
        this.params = params;
    }
    

// Implementation of ElGamalPrivateKey interface
//...........................................................................

    public BigInteger getX()
    {
        return this.x;
    }
    

// Implementation of ElGamalKey interface
//...........................................................................

    public ElGamalParams getParams()
    {
        return this.params;
    }
    

// Implementation of Key interface
//...........................................................................

    public String getAlgorithm()
    {
        return "ElGamal";
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
            mos.write(this.params.getP());
            mos.write(this.params.getQ());
            mos.write(this.params.getG());
            mos.write(this.x);
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

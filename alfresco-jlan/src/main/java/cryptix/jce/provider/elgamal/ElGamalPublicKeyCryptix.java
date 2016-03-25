/* $Id: ElGamalPublicKeyCryptix.java,v 1.3 2000/02/10 01:31:43 gelderen Exp $
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
import cryptix.jce.ElGamalPublicKey;
import cryptix.jce.util.MPIOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;


/**
 * @version $Revision: 1.3 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
/*package*/ final class ElGamalPublicKeyCryptix
implements ElGamalPublicKey
{
    private final BigInteger y;
    private final ElGamalParams params;
    
    
    /*package*/ ElGamalPublicKeyCryptix(BigInteger y, ElGamalParams params)
    {
        this.y      = y;
        this.params = params;
    }
    
    
    public BigInteger getY()
    {
        return this.y;
    }
    
    
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
            mos.write(this.y);
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

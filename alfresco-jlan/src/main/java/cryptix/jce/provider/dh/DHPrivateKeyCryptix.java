/* $Id: DHPrivateKeyCryptix.java,v 1.1 2000/02/09 20:35:10 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.dh;


import cryptix.jce.util.MPIOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;


/**
 * @version $Revision: 1.1 $
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
/*package*/ final class DHPrivateKeyCryptix implements DHPrivateKey
{

// Instance variables
// ..........................................................................

    private final BigInteger x;
    
    
    private final DHParameterSpec params;


// Cosntructor
// ..........................................................................

    /*package*/ DHPrivateKeyCryptix(BigInteger x, DHParameterSpec params)
    {
        this.x      = x;
        this.params = params;
    }
    


// Interface javax.crypto.interfaces.DHPrivateKey
// ..........................................................................

    public BigInteger getX()
    {
        return this.x;
    }
    
    
// Interface javax.crypto.interfaces.DHKey
// ..........................................................................

    public DHParameterSpec getParams()
    {
        return this.params;
    }
    
    
// Interface java.security.Key
// ..........................................................................

    public String getAlgorithm()
    {
        return "DH";
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
            mos.write( BigInteger.valueOf(this.params.getL()) );            
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
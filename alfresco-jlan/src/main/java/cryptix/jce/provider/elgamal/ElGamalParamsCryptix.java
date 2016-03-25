/* $Id: ElGamalParamsCryptix.java,v 1.2 2000/01/20 14:59:28 gelderen Exp $
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
import java.math.BigInteger;


/**
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
/*package*/ final class ElGamalParamsCryptix
implements ElGamalParams
{

// Instance variables
//...........................................................................

    private final BigInteger p, q, g;
    

// Constructor
//...........................................................................

    /*package*/ ElGamalParamsCryptix(BigInteger p, BigInteger q, BigInteger g)
    {
        this.p = p;
        this.q = q;
        this.g = g;
    }
    

// Implementation of ElGamalParams interface
//...........................................................................

    public BigInteger getP()
    {
        return p;
    }
    

    public BigInteger getQ()
    {
        return q;
    }

    
    public BigInteger getG()
    {
        return g;
    }
}

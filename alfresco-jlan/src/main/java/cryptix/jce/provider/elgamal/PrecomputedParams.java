/* $Id: PrecomputedParams.java,v 1.4 2003/02/15 13:46:31 gelderen Exp $
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


import java.math.BigInteger;

import cryptix.jce.ElGamalParams;
import cryptix.jce.provider.util.Group;
import cryptix.jce.provider.util.Precomputed;


/**
 * @version $Revision: 1.4 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
/*package*/ final class PrecomputedParams
{
    /*package*/ static ElGamalParams get(int keysize)
    {
        Group g = Precomputed.getElGamalGroup(keysize);
        if( g==null)
            return null;
        else 
            return new ElGamalParamsCryptix(g.getP(), g.getQ(), g.getG());
    }
}

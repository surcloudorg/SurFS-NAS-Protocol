/* $Id: Group.java,v 1.1 2003/02/15 13:41:21 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 * 
 * Use, modification, copying and distribution of this software is subject 
 * the terms and conditions of the Cryptix General Licence. You should have 
 * received a copy of the Cryptix General Licence along with this library; 
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.util;


import java.math.BigInteger;


/**
 * Immutable.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class Group
{
    private BigInteger
        p,
        q,
        g;
        
    /*package*/ Group(BigInteger p, BigInteger q, BigInteger g)
    {
        this.p = p;
        this.q = q;
        this.g = g;
    }
    
    
    public BigInteger getP()
    {
        return this.p;
    }
    
    
    public BigInteger getQ()
    {
        return this.q;
    }
    
    
    public BigInteger getG()
    {
        return this.g;
    }
}

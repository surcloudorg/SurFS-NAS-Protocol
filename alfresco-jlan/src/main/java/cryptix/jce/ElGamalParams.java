/* $Id: ElGamalParams.java,v 1.6 2000/01/20 14:59:22 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 * 
 * Use, modification, copying and distribution of this software is subject 
 * the terms and conditions of the Cryptix General Licence. You should have 
 * received a copy of the Cryptix General Licence along with this library; 
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce;


import java.math.BigInteger;


/**
 * @version $Revision: 1.6 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public interface ElGamalParams
{
    BigInteger getP();
    BigInteger getQ();
    BigInteger getG();
}
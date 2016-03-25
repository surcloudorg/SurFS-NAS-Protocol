/* $Id: ElGamalParameterGenerator.java,v 1.2 2000/01/20 14:59:28 gelderen Exp $
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

import java.security.AlgorithmParameters;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;


/**
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class ElGamalParameterGenerator 
extends AlgorithmParameterGeneratorSpi
{

// Constants    
//...........................................................................

    private static final int 
        KEYSIZE_MIN     =   384,
        KEYSIZE_MAX     = 16384,
        KEYSIZE_DEFAULT = 16384;


// AlgorithmParameterGeneratorSpi methods
//...........................................................................

    protected void engineInit(int size, SecureRandom random)
    {
        throw new RuntimeException("NYI");
    }
    
    
    protected void engineInit(AlgorithmParameterSpec genParamSpec,
                              SecureRandom random)
    throws InvalidAlgorithmParameterException
    {
        throw new RuntimeException("NYI");
    }
    
    
    protected AlgorithmParameters engineGenerateParameters()
    {
        throw new RuntimeException("NYI");
    }
}

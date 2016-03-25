/* $Id: ElGamalAlgorithm.java,v 1.5 2001/08/09 21:58:05 edwin Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.elgamal;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This class implements the ElGamal algorithm as it is specified in
 * the Handbook of Applied Cryptography by A. Menezes, P. van Oorchot
 * and S. Vanstone in chapter 8.4.
 *
 * We do not use the same k between consecutive encryptions as pointed
 * out in note 8.23 (ii).
 *
 * @version $Revision: 1.5 $
 * @author Paul Waserbrot (pw@cryptix.org)
 */

final class ElGamalAlgorithm {
    
    private ElGamalAlgorithm(){}

    private static BigInteger generateK(BigInteger p) {
        BigInteger k;
        
        BigInteger ONE = BigInteger.valueOf(1L);
        BigInteger p_1 = p.subtract(ONE);
        SecureRandom sr = new SecureRandom();
        do {
            k = new BigInteger(p.bitLength(), sr);
        } while (k.compareTo(ONE) <= 0 || k.compareTo(p_1) >= 0);
        return k;
    }

    /**
     * A method that do the encryption using the ElGamal algorithm.
     *
     * The ciphertext is returned as an array of two BigIntegers.
     *
     * @param m the plaintext
     * @param p the modulus
     * @param g the base
     * @param a the private key
     */
    public static BigInteger [] encrypt(BigInteger m, BigInteger p, 
                                        BigInteger g, BigInteger a) {
        BigInteger k = generateK(p);

        try {
            BigInteger [] bia = new BigInteger[2];
            bia[0] = g.modPow(k, p);
            bia[1] = a.modPow(k, p).multiply(m).mod(p);
            return bia;
        } catch (ArithmeticException e) {
            throw new RuntimeException("PANIC: Should not happend!!");
        }
    }
    
    /**
     * A method that do the decryption using the ElGamal algorithm.
     *
     * The plaintext is returned as a BigInteger.
     *
     * @param bia a BigInteger array containing the ciphertext
     * @param p the modulus
     * @param a the private key
     */
    public static BigInteger decrypt(BigInteger [] bia, BigInteger p,
                                     BigInteger a) 
        throws ArithmeticException
    {
        return (bia[0].modPow(a, p).modInverse(p)).multiply(bia[1]).mod(p);
    }
}

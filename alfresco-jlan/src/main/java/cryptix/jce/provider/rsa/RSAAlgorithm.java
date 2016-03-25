/* $Id: RSAAlgorithm.java,v 1.5 2000/02/10 01:31:43 gelderen Exp $
 *
 * Copyright (C) 1995-1999 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


import java.math.BigInteger;


/**
 * A class that calculates the RSA algorithm. A single method is
 * used for encryption, decryption, signing and verification:
 * <ul>
 *   <li> for encryption and verification, the public exponent, <i>e</i>,
 *        should be given.
 *   <li> for decryption and signing, the private exponent, <i>d</i>,
 *        should be given.
 * </ul>
 * <p>
 * The purpose of having this as a separate class is to avoid duplication
 * between the RSA Cipher and Signature implementations.
 * <p>
 * <b>References:</b>
 * <ol>
 *   <li> Donald E. Knuth,
 *        <cite>The Art of Computer Programming</cite>,
 *        ISBN 0-201-03822-6 (v.2) pages 270-274.
 *        <p>
 *   <li> <cite>ANS X9.31, Appendix B</cite>.
 * </ol>
 *
 * @version $Revision: 1.5 $
 * @author David Hopwood
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @author Raif S. Naffah
 */
/*package*/ final class RSAAlgorithm
{

// Constants
//...........................................................................

    /** Not present in JDK 1.1 */
    private static final BigInteger ONE = BigInteger.valueOf(1L);


// Constructor
//...........................................................................

    /** static methods only */
    private RSAAlgorithm() {}


// Own methods
//...........................................................................

    /**
     * Computes the RSA algorithm. If <i>p</i> is null, straightforward
     * modular exponentiation is used.
     * <p>
     * Otherwise, this method uses the Chinese Remainder Theorem (CRT) to
     * compute the result given the known factorisation of the public
     * modulus <i>n</i> into two relatively prime factors <i>p</i> and <i>q</i>.
     * The arithmetic behind this method is detailed in [1] and [2].
     * <p>
     * The comments that follow, which are edited from the PGP
     * <samp>mpilib.c</samp> file <em>with p and q reversed</em>, make
     * the practical algorithmic implementation clearer:
     * <p>
     * <blockquote>
     *     Y = X**d (mod n) = X**d (mod pq)
     * </blockquote>
     * <p>
     * We form this by evaluating:
     * <blockquote>
     *     p2 = plain**d (mod p) and <br>
     *     q2 = plain**d (mod q)
     * </blockquote>
     * and then combining the two by the CRT.
     * <p>
     * Two optimisations of this are possible. First, we reduce X modulo p
     * and q before starting, since:
     * <blockquote>
     *    x**a (mod b) = (x (mod b))**a (mod b)
     * </blockquote>
     * <p>
     * Second, since we know the factorisation of p and q (trivially derived
     * from the factorisation of n = pq), and input is relatively prime to
     * both p and q, we can use Euler's theorem:
     * <blockquote>
     *     X**phi(m) = 1 (mod m),
     * </blockquote>
     * to throw away multiples of phi(p) or phi(q) in d. Letting
     * <blockquote>
     *     ep = d (mod phi(p)) and <br>
     *     eq = d (mod phi(q))
     * </blockquote>
     * then combining these two speedups, we only need to evaluate:
     * <blockquote>
     *     p2 = (X mod p)**ep (mod p) and <br>
     *     q2 = (X mod q)**eq (mod q).
     * </blockquote>
     * <p>
     * Now we need to apply the CRT. Starting with:
     * <blockquote>
     *     Y = p2 (mod p) and <br>
     *     Y = q2 (mod q)
     * </blockquote>
     * we can say that:
     * <blockquote>
     *     Y = q2 + kq
     * </blockquote>
     * and if we assume that:
     * <blockquote>
     *     0 <= q2 < q, then <br>
     *     0 <= Y < pq for some 0 <= k < p
     * </blockquote>
     * <p>
     * Since we want:
     * <blockquote>
     *     Y = p2 (mod p),
     * </blockquote>
     * then
     * <blockquote>
     *     kq = (p2 - q2) (mod q)
     * <blockquote>
     * <p>
     * Since p and q are relatively prime, q has a multiplicative inverse
     * u mod p. In other words, uq = 1 (mod p).
     * <p>
     * Multiplying by u on both sides gives:
     * <blockquote>
     *     k = u * (p2 - q2) (mod p)
     * </blockquote>
     * <p>
     * Once we have k, evaluating kq + q2 is trivial, and that gives
     * us the result.
     *
     * @param  X    the BigInteger to be used as input.
     * @param  n    the public modulus.
     * @param  exp  the exponent (e for encryption and verification,
     *              d for decryption and signing).
     * @param  p    the first factor of the public modulus.
     * @param  q    the second factor of the public modulus.
     * @param  u    the multiplicative inverse of q modulo p.
     * @return the result of the computation.
     */
    public static BigInteger rsa(BigInteger X, BigInteger n, BigInteger exp,
                                 BigInteger p, BigInteger q, BigInteger u)
    {
        if (p == null)
            return rsa(X, n, exp);
        
        // construct the two missing ints
        BigInteger primeExponentP = exp.mod(p.subtract(ONE));
        BigInteger primeExponentQ = exp.mod(q.subtract(ONE));
        
        return rsa(X, n, exp, p, q, primeExponentP, primeExponentQ, u);
    }


    public static BigInteger rsa(BigInteger X, 
                                 BigInteger modulus, 
                                 BigInteger exp,
                                 BigInteger primeP, 
                                 BigInteger primeQ,
                                 BigInteger primeExponentP,
                                 BigInteger primeExponentQ,
                                 BigInteger crtCoefficient)
    {
        // First check if u = (1/q) mod p; if not exchange p and q
        // before using CRT. This is needed for factors not generated/set
        // by cryptix.provider.rsa classes; eg. PGP applications.
        if( !crtCoefficient.equals(primeQ.modInverse(primeP)) )
        {
            BigInteger t;
            
            t = primeQ; primeQ = primeP; primeP = t;
            
            t              = primeExponentQ; 
            primeExponentQ = primeExponentP; 
            primeExponentP = t;
        }

        // Factors are known and usable by our CRT code.
        BigInteger p2 = X.mod(primeP).modPow(primeExponentP, primeP);
        BigInteger q2 = X.mod(primeQ).modPow(primeExponentQ, primeQ);

        if (p2.equals(q2))
            return q2;

        BigInteger k = (p2.subtract(q2).mod(primeP));
        BigInteger l = k.multiply(crtCoefficient).mod(primeP);
        return primeQ.multiply(l).add(q2);
    }


    /**
     * Computes the RSA algorithm, without using the Chinese Remainder
     * Theorem.
     *
     * @param  X    the BigInteger to be used as input.
     * @param  n    the public modulus.
     * @param  exp  the exponent (e for encryption and verification,
     *              d for decryption and signing).
     * @return the result of the computation.
     */
    public static BigInteger rsa(BigInteger X, BigInteger n, BigInteger exp)
    {
        return X.modPow(exp, n);
    }
}

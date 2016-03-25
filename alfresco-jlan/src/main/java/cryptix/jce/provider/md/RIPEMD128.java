/* $Id: RIPEMD128.java,v 1.7 2001/06/25 15:39:55 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */

package cryptix.jce.provider.md;


/**
 * An implementation of the RIPEMD-128 algorithm as described in the
 * references below:
 *
 * <ul>
 * <li> Hans Dobbertin, Antoon Bosselaers and Bart Preneel,
 *      "RIPEMD-160: A Strengthened Version of RIPEMD," 18 April 1996.
 *      A joint publication by the German Information Security Agency
 *      (POB 20 03 63, D-53133 Bonn, Germany)
 *      and the Katholieke Universiteit Leuven, ESAT-COSIC
 *      (K. Mercierlaan 94, B-3001 Heverlee, Belgium).</li>
 * <li> <a href="http://www.esat.kuleuven.ac.be/~bosselae/rmd128.txt">
 *      Pseudo-code for RIPEMD-128</a></li>
 * </ul>
 *
 * @version $Revision: 1.7 $
 * @author  Raif S. Naffah
 * @author  David Hopwood
 * @author  Jeroen C. van Gelderen
 * @since   Cryptix 2.2.2
 */
public final class RIPEMD128
extends PaddingMD
implements Cloneable
{

// Constants
//...........................................................................

    /**
     * Constants for the transform method. They're defined as static because
     * they're common to all RIPEMD128 instantiated objects; and final since
     * they're non-modifiable.
     */
    private static final int[]
        // selection of message word
        R  = {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
                7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
                3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
                1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2},
        Rp = {  5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
                6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
               15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
                8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14},

        // amount for rotate left (rol)
        S  = { 11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
                7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
               11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
               11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12},
        Sp = {  8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
                9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
                9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
               15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8};



// Instance variables
//...........................................................................

    /** 128-bit h0, h1, h2, h3 (interim result) */
    private int[] context = new int[4];

    /** 512 bits work buffer = 16 x 32-bit words */
    private int[] X = new int[16];



// Constructors
//...........................................................................

    public RIPEMD128()
    {
        super(16, PaddingMD.MODE_MD);
        coreReset();
    }


    private RIPEMD128(RIPEMD128 src)
    {
        super(src);
        this.context = (int[])src.context.clone();
        this.X       = (int[])src.X.clone();
    }


    public Object clone()
    {
        return new RIPEMD128(this);
    }


// Concreteness
//...........................................................................

    protected void coreDigest(byte[] buf, int off)
    {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                buf[off +(i * 4 + j)] = (byte)((context[i] >>> (8 * j)) & 0xFF);
    }


    protected void coreReset()
    {
        // magic RIPEMD128 initialisation constants
        context[0] = 0x67452301;
        context[1] = 0xEFCDAB89;
        context[2] = 0x98BADCFE;
        context[3] = 0x10325476;
    }



    /**
     * RIPEMD128 basic transformation.
     * <p>
     * Transforms context based on 64 bytes from input block starting from
     * the offset'th byte.
     */
    protected void coreUpdate(byte[] block, int offset)
    {
        int A, B, C, D, Ap, Bp, Cp, Dp, T, s, i;

        // encode 64 bytes from input block into an array of 16 unsigned
        // integers.
        for (i = 0; i < 16; i++)
            X[i] = (block[offset++] & 0xFF)       |
                   (block[offset++] & 0xFF) <<  8 |
                   (block[offset++] & 0xFF) << 16 |
                   (block[offset++] & 0xFF) << 24;

        A = Ap = context[0];
        B = Bp = context[1];
        C = Cp = context[2];
        D = Dp = context[3];

        // rounds 0...15
        for (i = 0; i < 16; i++)
        {
            s = S[i];
            T = A + (B ^ C ^ D) + X[i];
            A = D; D = C; C = B; B = T << s | T >>> (32 - s);

            s = Sp[i];
            T = Ap + ((Bp & Dp) | (Cp & ~Dp)) + X[Rp[i]] + 0x50A28BE6;
            Ap = Dp; Dp = Cp; Cp = Bp; Bp = T << s | T >>> (32 - s);
        }
        // rounds 16...31
        for (i = 16; i < 32; i++)
        {
            s = S[i];
            T = A + ((B & C) | (~B & D)) + X[R[i]] + 0x5A827999;
            A = D; D = C; C = B; B = T << s | T >>> (32 - s);

            s = Sp[i];
            T = Ap + ((Bp | ~Cp) ^ Dp) + X[Rp[i]] + 0x5C4DD124;
            Ap = Dp; Dp = Cp; Cp = Bp; Bp = T << s | T >>> (32 - s);
        }
        // rounds 32...47
        for (i = 32; i < 48; i++)
        {
            s = S[i];
            T = A + ((B | ~C) ^ D) + X[R[i]] + 0x6ED9EBA1;
            A = D; D = C; C = B; B = T << s | T >>> (32 - s);

            s = Sp[i];
            T = Ap + ((Bp & Cp) | (~Bp & Dp)) + X[Rp[i]] + 0x6D703EF3;
            Ap = Dp; Dp = Cp; Cp = Bp; Bp = T << s | T >>> (32 - s);
        }
        // rounds 48...63
        for (i = 48; i < 64; i++)
        {
            s = S[i];
            T = A + ((B & D) | (C & ~D)) + X[R[i]] + 0x8F1BBCDC;
            A = D; D = C; C = B; B = T << s | T >>> (32 - s);

            s = Sp[i];
            T = Ap + (Bp ^ Cp ^ Dp) + X[Rp[i]];
            Ap = Dp; Dp = Cp; Cp = Bp; Bp = T << s | T >>> (32 - s);
        }
        T = context[1] + C + Dp;
        context[1] = context[2] + D + Ap;
        context[2] = context[3] + A + Bp;
        context[3] = context[0] + B + Cp;
        context[0] = T;
    }
}
/* $Id: Square.java,v 1.4 2000/01/20 14:59:24 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.cipher;


import java.security.InvalidKeyException;
import java.security.Key;


/**
 * The Square algorithm.
 * <p>
 * Square is a cipher algorithm developed by Joan Daemen <Daemen.J@banksys.com>
 * and Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * <p>
 * <b>References:</b>
 * <p>
 * <blockquote>
 * <ul>
 *    <li>The
 *        <a href="http://www.esat.kuleuven.ac.be/%7Erijmen/square/">
 *        Square home page</a>
 *        has up-to-date comments, implementations, and certification data.
 *    <li>J. Daemen, L.R. Knudsen, V. Rijmen,
 *        "<a href="http://www.esat.kuleuven.ac.be/%7Erijmen/downloadable/square/fse.ps.gz">
 *        The block cipher Square</a>,"
 *        <cite>Fast Software Encryption</cite>,
 *        LNCS 1267, E. Biham, Ed., Springer-Verlag, 1997, pp. 149-165.
 * </ul>
 * </blockquote>
 *
 * @version $Revision: 1.4 $
 * @author  Raif S. Naffah
 * @author  Paulo S.L.M. Barreto
 * @author  David Hopwood
 * @author  Jeroen C. van Gelderen
 */
public final class Square
extends BlockCipher
{

// Static variables and constants
//............................................................................

    private static final int
        BLOCK_SIZE = 16,
        KEY_LENGTH = 10,
        R          =  8; // nof rounds

    /** Encryption and decryption Square S-Box values */
    private static final byte[]
        SE = new byte[256],
        SD = new byte[256];

    /** Transposition boxes for encryption and decryption */
    private static final int[]
        TE = new int[256],
        TD = new int[256];

    private static final int ROOT = 0x1F5;          // for generating GF(2**8)

    private static final int[] OFFSET = new int[R];


// Static code to build some tables
//............................................................................

    static
    {
        int i, j;

        //
        // Generate exp and log tables used in multiplication over GF(2 ** m)
        //
        byte[] exp = new byte[256];
        byte[] log = new byte[256];

        exp[0] = 1;
        for (i = 1; i < 256; i++) {
            j = exp[i - 1] << 1;
            if ((j & 0x100) != 0)
                j ^= ROOT;      // reduce j (mod ROOT)

            exp[i] = (byte)j;
            log[j & 0xFF] = (byte)i;
        }

        //
        // Compute the substitution box SE[] and its inverse SD[]
        // based on F(x) = x**{-1} plus affine transform of the output.
        //
        SE[0] = 0;
        SE[1] = 1;
        for (i = 2; i < 256; i++)
            SE[i] = exp[(255 - log[i]) & 0xFF];

        //
        // Let SE[i] be represented as an 8-row vector V over GF(2);
        // the affine transformation is A * V + T, where the rows of
        // the 8 x 8 matrix A are contained in trans[0]...trans[7]
        // and the 8-row vector T is contained in 0xB1.
        //
        int[] trans = {0x01, 0x03, 0x05, 0x0F, 0x1F, 0x3D, 0x7B, 0xD6};
        int u, v;
        for (i = 0; i < 256; i++) {
            v = 0xB1;                           // the affine part of the transform
            for (j = 0; j < 8; j++) {
                u = SE[i] & trans[j] & 0xFF;    // column-wise multiplication over GF(2)
                u ^= u >>> 4;                   // sum of all bits of u over GF(2)
                u ^= u >>> 2;
                u ^= u >>> 1;
                u &= 1;
                v ^= u << j;                    // row alignment of the result
            }
            SE[i] = (byte) v;
            SD[v] = (byte) i;                   // inverse substitution box
        }

        //
        // Generate the OFFSET values.
        //
        OFFSET[0] = 1;
        for (i = 1; i < R; i++) {
            OFFSET[i] = mul(OFFSET[i - 1], 2);
            OFFSET[i - 1] <<= 24;
        }
        OFFSET[R - 1] <<= 24;

        //
        // Generate the TE and TD transposition boxes.
        // Notes:
        // (1) The function mul below computes the product of two
        //     elements of GF(2 ** 8) with ROOT as reduction polynomial
        //     (see implementation below in Square's Own Methods section)
        // (2) the values used in computing the TE and TD values are
        //     the GF(2 ** 8) coefficients of the diffusion polynomial c(x)
        //     and its inverse (modulo x ** 4 + 1) d(x), defined in sections
        //     2.1 and 4 of the algorithm designers' paper (see References
        //     above).
        //
        int se, sd;
        for (i = 0; i < 256; i++) {
            se = SE[i] & 0xFF;
            sd = SD[i] & 0xFF;
            TE[i] =  SE[i & 3] == 0 ? 0 :
            mul(se, 2) << 24 | se << 16 | se << 8 | mul(se, 3);
            TD[i] =  SD[i & 3] == 0 ? 0 :
            mul(sd, 14) << 24 | mul(sd, 9) << 16 | mul(sd, 13) << 8 | mul(sd, 11);
        }
    }


// Instance variables
//............................................................................

    /** This instance's Square key schedule. */
    private int[][] sKey = new int[R + 1][4];

    /** Are we decrypting? */
    private boolean decrypt;


// Constructor
//............................................................................

    public Square() {
       super(BLOCK_SIZE);
    }


// Implementation of abstract methods
//............................................................................

    protected void coreInit(Key key, boolean decrypt)
    throws InvalidKeyException
    {
        makeKey(key, !decrypt);
        this.decrypt = decrypt;
    }


    protected void coreCrypt(byte[] in, int inOffset, byte[] out, int outOffset)
    {
        if(decrypt)
            square(in, inOffset, out, outOffset, TD, SD);
        else
            square(in, inOffset, out, outOffset, TE, SE);
    }


//............................................................................

    /**
     * Expands a user-key to a working key schedule.
     *
     * @param  key          the user-key object to use.
     * @param  doEncrypt    true for encryption, false for decryption.
     * @exception InvalidKeyException if one of the following occurs: <ul>
     *                <li> key.getEncoded() == null;
     *                <li> The length of the user key array is not KEY_LENGTH.
     *              </ul>
     */
    private void makeKey(Key key, boolean doEncrypt)
    throws InvalidKeyException {

        byte[] userkey = key.getEncoded();
        if (userkey == null)
            throw new InvalidKeyException("Null user key");

        if (userkey.length != BLOCK_SIZE)
            throw new InvalidKeyException("Invalid user key length");

        int i, j = 0;
        if (doEncrypt) {
            for (i = 0; i < 4; i++)
                sKey[0][i] = (userkey[j++] & 0xFF) << 24 | (userkey[j++] & 0xFF) << 16 |
                             (userkey[j++] & 0xFF) <<  8 | (userkey[j++] & 0xFF);

            for (i = 1; i < R + 1; i++) {
                j = i - 1;
                sKey[i][0] = sKey[j][0] ^ rot32L(sKey[j][3], 8) ^ OFFSET[j];
                sKey[i][1] = sKey[j][1] ^ sKey[i][0];
                sKey[i][2] = sKey[j][2] ^ sKey[i][1];
                sKey[i][3] = sKey[j][3] ^ sKey[i][2];

                transform(sKey[j], sKey[j]);
            }
        } else {
            int[][] tKey = new int[R + 1][4];

            // apply the key evolution function
            for (i = 0; i < 4; i++)
                tKey[0][i] = (userkey[j++] & 0xFF) << 24 | (userkey[j++] & 0xFF) << 16 |
                             (userkey[j++] & 0xFF) <<  8 | (userkey[j++] & 0xFF);

            for (i = 1; i < R + 1; i++) {
                j = i - 1;
                tKey[i][0] = tKey[j][0] ^ rot32L(tKey[j][3], 8) ^ OFFSET[j];
                tKey[i][1] = tKey[j][1] ^ tKey[i][0];
                tKey[i][2] = tKey[j][2] ^ tKey[i][1];
                tKey[i][3] = tKey[j][3] ^ tKey[i][2];
            }
            for (i = 0; i < R; i++)
                System.arraycopy(tKey[R - i], 0, sKey[i], 0, 4);

            transform(tKey[0], sKey[R]);
        }
    }


    /**
     * Applies the Theta function to an input <i>in</i> in order to
     * produce in <i>out</i> an internal session sub-key.
     * <p>
     * Both <i>in</i> and <i>out</i> are arrays of four ints.
     * <p>
     * Pseudo-code is:
     * <pre>
     *    for (i = 0; i < 4; i++) {
     *        out[i] = 0;
     *        for (j = 0, n = 24; j < 4; j++, n -= 8) {
     *            k = mul(in[i] >>> 24, G[0][j]) ^
     *                mul(in[i] >>> 16, G[1][j]) ^
     *                mul(in[i] >>>  8, G[2][j]) ^
     *                mul(in[i]       , G[3][j]);
     *            out[i] ^= k << n;
     *        }
     *    }
     * </pre>
     */
    private static void transform (int[] in, int[] out) {
        int l3, l2, l1, l0, m;
        for (int i = 0; i < 4; i++) {
            l3 = in[i];
            l2 = l3 >>>  8;
            l1 = l3 >>> 16;
            l0 = l3 >>> 24;
            m  = ((mul(l0, 2) ^ mul(l1, 3) ^ l2 ^ l3) & 0xFF) << 24;
            m ^= ((l0 ^ mul(l1, 2) ^ mul(l2, 3) ^ l3) & 0xFF) << 16;
            m ^= ((l0 ^ l1 ^ mul(l2, 2) ^ mul(l3, 3)) & 0xFF) <<  8;
            m ^= (mul(l0, 3) ^l1 ^ l2 ^ mul(l3, 2)  ) & 0xFF;
            out[i] = m;
        }
    }


    /**
     * Left rotate a 32-bit chunk.
     *
     * @param  x    the 32-bit data to rotate
     * @param  s    number of places to left-rotate by
     * @return the newly permutated value.
     */
    private static int rot32L (int x, int s) { return x << s | x >>> (32 - s); }


    /**
     * Right rotate a 32-bit chunk.
     *
     * @param  x    the 32-bit data to rotate
     * @param  s    number of places to right-rotate by
     * @return the newly permutated value.
     */
    private static int rot32R (int x, int s) { return x >>> s | x << (32 - s); }


    /**
     * Returns the product of two binary numbers a and b, using
     * the generator ROOT as the modulus: p = (a * b) mod ROOT.
     * ROOT Generates a suitable Galois Field in GF(2 ** 8).
     * <p>
     * For best performance call it with abs(b) < abs(a).
     *
     * @param  a    operand for multiply.
     * @param  b    operand for multiply.
     * @return the result of (a * b) % ROOT.
     */
    private static final int mul (int a, int b) {
        if (a == 0)
            return 0;

        a &= 0xFF;
        b &= 0xFF;
        int p = 0;
        while (b != 0) {
            if ((b & 0x01) != 0)
                p ^= a;
            a <<= 1;
            if (a > 0xFF)
                a ^= ROOT;
            b >>>= 1;
        }
        return p & 0xFF;
    }


    /**
     * Applies the Square algorithm (for both encryption and decryption since
     * it is the same) on a 128-bit plain/cipher text into a same length cipher/
     * plain text using the Square formulae, relevant sub-keys, transposition
     * and S-Box values.
     *
     * @param  in       contains the plain-text 128-bit block.
     * @param  off      start index within input where data is considered.
     * @param  out      will contain the cipher-text block.
     * @param  outOff   index in out where cipher-text starts.
     * @param  T        reference to either the encryption (TE) or decryption
     *                  (TD) transposition vector.
     * @param  S        reference to either the encryption (SE) or decryption
     *                  (SD) S-Box values.
     */
    private void
    square (byte[] in, int off, byte[] out, int outOff, int[] T, byte[] S) {

        int a = (in[off++] & 0xFF) << 24 | (in[off++] & 0xFF) << 16 |
                (in[off++] & 0xFF) <<  8 | (in[off++] & 0xFF);
        int b = (in[off++] & 0xFF) << 24 | (in[off++] & 0xFF) << 16 |
                (in[off++] & 0xFF) <<  8 | (in[off++] & 0xFF);
        int c = (in[off++] & 0xFF) << 24 | (in[off++] & 0xFF) << 16 |
                (in[off++] & 0xFF) <<  8 | (in[off++] & 0xFF);
        int d = (in[off++] & 0xFF) << 24 | (in[off++] & 0xFF) << 16 |
                (in[off++] & 0xFF) <<  8 | (in[off++] & 0xFF);

        int aa, bb, cc, dd;
        int i, j, k;

        a ^= sKey[0][0];
        b ^= sKey[0][1];
        c ^= sKey[0][2];
        d ^= sKey[0][3];

        // R - 1 full rounds
        for (i = 1; i < R; i++) {
            aa =       T[(a >>> 24) & 0xFF]      ^
                rot32R(T[(b >>> 24) & 0xFF],  8) ^
                rot32R(T[(c >>> 24) & 0xFF], 16) ^
                rot32R(T[(d >>> 24) & 0xFF], 24) ^ sKey[i][0];

            bb =       T[(a >>> 16) & 0xFF]      ^
                rot32R(T[(b >>> 16) & 0xFF],  8) ^
                rot32R(T[(c >>> 16) & 0xFF], 16) ^
                rot32R(T[(d >>> 16) & 0xFF], 24) ^ sKey[i][1];

            cc =       T[(a >>>  8) & 0xFF]      ^
                rot32R(T[(b >>>  8) & 0xFF],  8) ^
                rot32R(T[(c >>>  8) & 0xFF], 16) ^
                rot32R(T[(d >>>  8) & 0xFF], 24) ^ sKey[i][2];

            dd =       T[ a         & 0xFF]      ^
                rot32R(T[ b         & 0xFF],  8) ^
                rot32R(T[ c         & 0xFF], 16) ^
                rot32R(T[ d         & 0xFF], 24) ^ sKey[i][3];

            a = aa;
            b = bb;
            c = cc;
            d = dd;
        }
        // last round (diffusion becomes only transposition)
        for (i = 0, j = 24; i < 4; i++, j -= 8) {
            k = (S[(a >>> j) & 0xFF] & 0xFF) << 24 |
                (S[(b >>> j) & 0xFF] & 0xFF) << 16 |
                (S[(c >>> j) & 0xFF] & 0xFF) <<  8 |
                (S[(d >>> j) & 0xFF] & 0xFF);
            k ^= sKey[R][i];

            out[outOff++] = (byte)((k >>> 24) & 0xFF);
            out[outOff++] = (byte)((k >>> 16) & 0xFF);
            out[outOff++] = (byte)((k >>>  8) & 0xFF);
            out[outOff++] = (byte) (k         & 0xFF);
        }
    }
}

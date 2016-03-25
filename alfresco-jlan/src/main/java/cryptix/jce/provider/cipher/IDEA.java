/* $Id: IDEA.java,v 1.7 2000/02/10 14:50:47 gelderen Exp $
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
 * IDEA is a block cipher with a key length of 16 bytes and a block length of
 * 8 bytes. It is highly popular, being the original cipher in PGP, and has
 * received a lot of cryptanalytic attention.
 * <p>
 * IDEA was written by Dr. X. Lai and Prof. J. Massey.
 * <p>
 * References:<br>
 * <ul>
 * <li>See the
 *     <a href="http://www.ascom.ch/infosec/idea.html">IDEA page</a>
 *     for more details</li>
 *
 * <li>The algorithm is patented by
 *     <a href="http://www.ascom.ch/">Ascom Systec Ltd</a>
 *     (applied for May 1991), and is
 *     <a href="http://www.ascom.ch/infosec/idea.html">licensable</a></li>
 * </ul>
 *
 * @version $Revision: 1.7 $
 * @author  David Hopwood
 * @author  Jeroen C. van Gelderen
 * @author  Raif S. Naffah
 * @author  Systemics Ltd
 */
public final class IDEA
extends BlockCipher
{
// Static variables and constants
//............................................................................

    private static final int
        ROUNDS              = 8,
        BLOCK_SIZE          = 8,
        KEY_LENGTH          = 16,
        INTERNAL_KEY_LENGTH = 52;


// Instance variables
//............................................................................

    /** The key schedule. */
    private short[] ks = new short[INTERNAL_KEY_LENGTH];


// Constructors
//............................................................................

    public IDEA()
    {
        super(BLOCK_SIZE);
    }


// Implementation of abstract methods
//............................................................................

    protected void coreInit(Key key, boolean decrypt)
    throws InvalidKeyException
    {
        makeKey(key);
        if(decrypt) invertKey();
    }


    protected void coreCrypt(byte[] in, int inOffset, byte[] out, int outOffset)
    {
        blockEncrypt(in, inOffset, out, outOffset);
    }


// Private parts
//............................................................................

    /**
     * IDEA encryption/decryption algorithm using the current key schedule.
     *
     * @param  in       an array containing the plaintext block
     * @param  inOffset the starting offset of the plaintext block
     * @param  out      an array containing the ciphertext block
     * @param  inOffset the starting offset of the ciphertext block
     */
    private void blockEncrypt( byte[] in, int inOffset,
                               byte[] out, int outOffset )
    {
        short
            x1 = (short)(((in[inOffset++]&0xFF) << 8) | (in[inOffset++]&0xFF)),
            x2 = (short)(((in[inOffset++]&0xFF) << 8) | (in[inOffset++]&0xFF)),
            x3 = (short)(((in[inOffset++]&0xFF) << 8) | (in[inOffset++]&0xFF)),
            x4 = (short)(((in[inOffset++]&0xFF) << 8) | (in[inOffset  ]&0xFF));

        short s2, s3;

        int i     = 0;
        int round = ROUNDS;

        while (round-- > 0)
        {
            x1 = mul(x1, ks[i++]);
            x2 += ks[i++];
            x3 += ks[i++];
            x4 = mul(x4, ks[i++]);

            s3 = x3;
            x3 = mul(x1 ^ x3, ks[i++]);
            s2 = x2;
            x2 = mul(x3 + (x2 ^ x4), ks[i++]);
            x3 += x2;

            x1 ^= x2;
            x4 ^= x3;
            x2 ^= s3;
            x3 ^= s2;
        }

        s2 = mul(x1, ks[i++]);
        out[outOffset++] = (byte)(s2 >>> 8);
        out[outOffset++] = (byte) s2;
        s2 = (short)(x3 + ks[i++]);
        out[outOffset++] = (byte)(s2 >>> 8);
        out[outOffset++] = (byte) s2;
        s2 = (short)(x2 + ks[i++]);
        out[outOffset++] = (byte)(s2 >>> 8);
        out[outOffset++] = (byte) s2;
        s2 = mul(x4, ks[i]);
        out[outOffset++] = (byte)(s2 >>> 8);
        out[outOffset  ] = (byte) s2;
    }


    private void makeKey(Key key)
    throws InvalidKeyException
    {
        byte[] userkey = key.getEncoded();
        if( userkey == null )
            throw new InvalidKeyException("Null user key");

        if( userkey.length != KEY_LENGTH )
            throw new InvalidKeyException("Invalid user key length");

        // Expand user key of 128 bits to full 832 bits of encryption key.
        ks[0] = (short)((userkey[ 0] & 0xFF) << 8 | (userkey[ 1] & 0xFF));
        ks[1] = (short)((userkey[ 2] & 0xFF) << 8 | (userkey[ 3] & 0xFF));
        ks[2] = (short)((userkey[ 4] & 0xFF) << 8 | (userkey[ 5] & 0xFF));
        ks[3] = (short)((userkey[ 6] & 0xFF) << 8 | (userkey[ 7] & 0xFF));
        ks[4] = (short)((userkey[ 8] & 0xFF) << 8 | (userkey[ 9] & 0xFF));
        ks[5] = (short)((userkey[10] & 0xFF) << 8 | (userkey[11] & 0xFF));
        ks[6] = (short)((userkey[12] & 0xFF) << 8 | (userkey[13] & 0xFF));
        ks[7] = (short)((userkey[14] & 0xFF) << 8 | (userkey[15] & 0xFF));

        for (int i = 0, zoff = 0, j = 8; j < INTERNAL_KEY_LENGTH; i &= 7, j++)
        {
            i++;
            ks[i + 7 + zoff] = (short)((ks[(i & 7) + zoff] << 9) |
                ((ks[((i + 1) & 7) + zoff] >>> 7) & 0x1FF));
            zoff += i & 8;
        }
    }


    private void invertKey()
    {
        int i, j = 4, k = INTERNAL_KEY_LENGTH - 1;
        short[] temp = new short[INTERNAL_KEY_LENGTH];
        temp[k--] = inv(ks[3]);
        temp[k--] = (short) -ks[2];
        temp[k--] = (short) -ks[1];
        temp[k--] = inv(ks[0]);
        for (i = 1; i < ROUNDS; i++, j += 6)
        {
            temp[k--] = ks[j + 1];
            temp[k--] = ks[j];
            temp[k--] = inv(ks[j + 5]);
            temp[k--] = (short) -ks[j + 3];
            temp[k--] = (short) -ks[j + 4];
            temp[k--] = inv(ks[j + 2]);
        }

        temp[k--] = ks[j + 1];
        temp[k--] = ks[j];
        temp[k--] = inv(ks[j + 5]);
        temp[k--] = (short) -ks[j + 4];
        temp[k--] = (short) -ks[j + 3];
        temp[k--] = inv(ks[j + 2]);
        System.arraycopy(temp, 0, ks, 0, INTERNAL_KEY_LENGTH);
    }


    private static short inv( short xx )
    {
        int x = xx & 0xFFFF;         // only lower 16 bits
        if (x <= 1)
            return (short)x;         // 0 and 1 are self-inverse

        int t1 = 0x10001 / x;        // Since x >= 2, this fits into 16 bits
        int y = 0x10001 % x;
        if (y == 1)
            return (short)(1 - t1);

        int t0 = 1;
        int q;
        do
        {
            q = x / y;
            x = x % y;
            t0 += q * t1;
            if (x == 1)
                return (short)t0;
            q = y / x;
            y %= x;
            t1 += q * t0;
        }
        while (y != 1);

        return (short)(1 - t1);
    }


    private static short mul( int a, int b )
    {
        a &= 0xFFFF;
        b &= 0xFFFF;
        int p;
        if (a != 0)
        {
            if (b != 0)
            {
                p = a * b;
                b = p & 0xFFFF;
                a = p >>> 16;
                return (short)(b - a + (b < a ? 1 : 0));
            }
            else
            {
                return (short)(1 - a);
            }
        }
        else
        {
            return (short)(1 - b);
        }
    }
}

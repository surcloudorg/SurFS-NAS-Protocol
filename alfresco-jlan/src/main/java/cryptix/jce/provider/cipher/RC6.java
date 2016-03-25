/* $Id: RC6.java,v 1.2 2000/02/10 14:02:59 gelderen Exp $
 *
 * Copyright (C) 1999-2000 The Cryptix Foundation Limited.
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
 * Simple implementation of Ron Rivest's RC6 cipher. Use of this algorithm
 * may be subject to licensing restrictions imposed by the RC6 inventor.
 * <p>
 * <a href="http://www.rsa.com/rsalabs/aes/">
 * http://www.rsa.com/rsalabs/aes/</a>
 *
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class RC6 extends BlockCipher
{

// Constants
//...........................................................................

    /** Number of rounds */
    private static final int
        ROUNDS     = 20,
        BLOCK_SIZE = 16;

    /** Magic constants */
    private static final int
        P = 0xB7E15163,
        Q = 0x9E3779B9;


// Instance variables
//...........................................................................

    /** Subkeys */
    private int[] S = new int[2*ROUNDS + 4];

    /** Encrypt (false) or decrypt mode (true) */
    private boolean decrypt;


// Constructor
//...........................................................................

    public RC6()
    {
        super(BLOCK_SIZE);
    }


// BlockCipher abstract method implementation
//...........................................................................

    protected void coreInit(Key key, boolean decrypt)
    throws InvalidKeyException
    {
        if( key==null )
            throw new InvalidKeyException("Key missing");

        if( !key.getFormat().equalsIgnoreCase("RAW") )
            throw new InvalidKeyException("Wrong format: RAW bytes needed");

        byte[] userkey = key.getEncoded();
        if(userkey == null)
            throw new InvalidKeyException("RAW bytes missing");

        int len = userkey.length ;
        if( len != 16 && len != 24 && len!=32 )
            throw new InvalidKeyException("Invalid user key length");

        generateSubKeys( userkey );
        this.decrypt = decrypt;
    }


    /**
     * Encrypt or decrypt a single block (16 bytes), depending on
     * the current mode and key.
     *
     * Input and output buffer may (partially) overlap.
     *
     * Expects valid parameters only.
     *
     * @param  in        input data
     * @param  inOffset  offset where data starts
     * @param  out       output buffer
     * @param  outOffset offset where processed data is written
     */
    protected final void coreCrypt(byte[] in, int inOffset,
                                   byte[] out, int outOffset)
    {
        // Pack bytes into integers
        int A = ((in[inOffset++] & 0xFF)      ) |
                ((in[inOffset++] & 0xFF) <<  8) |
                ((in[inOffset++] & 0xFF) << 16) |
                ((in[inOffset++]       ) << 24);
        int B = ((in[inOffset++] & 0xFF)      ) |
                ((in[inOffset++] & 0xFF) <<  8) |
                ((in[inOffset++] & 0xFF) << 16) |
                ((in[inOffset++]       ) << 24);
        int C = ((in[inOffset++] & 0xFF)      ) |
                ((in[inOffset++] & 0xFF) <<  8) |
                ((in[inOffset++] & 0xFF) << 16) |
                ((in[inOffset++]       ) << 24);
        int D = ((in[inOffset++] & 0xFF)      ) |
                ((in[inOffset++] & 0xFF) <<  8) |
                ((in[inOffset++] & 0xFF) << 16) |
                ((in[inOffset  ]       ) << 24);

        int t, u;

        if(decrypt)
        {
            C -= S[2*ROUNDS+3];
            A -= S[2*ROUNDS+2];
            for(int i=2*ROUNDS+2; i>2; )
            {
                t = D; D = C; C = B; B = A; A = t;
                u = rotl( D*(2*D+1), 5 );
                t = rotl( B*(2*B+1), 5 );
                C = rotr( C-S[--i], t ) ^ u;
                A = rotr( A-S[--i], u ) ^ t;
            }
            D -= S[1];
            B -= S[0];
        }
        else
        {
            B += S[0];
            D += S[1];
            for(int i=1; i<=2*ROUNDS; )
            {
                t = rotl( B*(2*B+1), 5 );
                u = rotl( D*(2*D+1), 5 );
                A = rotl( (A^t), u ) + S[++i];
                C = rotl( (C^u), t ) + S[++i];
                t = A; A=B; B=C; C=D; D=t;
            }
            A += S[2*ROUNDS+2];
            C += S[2*ROUNDS+3];
        }

        out[outOffset++] = (byte)(A       );
        out[outOffset++] = (byte)(A >>>  8);
        out[outOffset++] = (byte)(A >>> 16);
        out[outOffset++] = (byte)(A >>> 24);

        out[outOffset++] = (byte)(B       );
        out[outOffset++] = (byte)(B >>>  8);
        out[outOffset++] = (byte)(B >>> 16);
        out[outOffset++] = (byte)(B >>> 24);

        out[outOffset++] = (byte)(C       );
        out[outOffset++] = (byte)(C >>>  8);
        out[outOffset++] = (byte)(C >>> 16);
        out[outOffset++] = (byte)(C >>> 24);

        out[outOffset++] = (byte)(D       );
        out[outOffset++] = (byte)(D >>>  8);
        out[outOffset++] = (byte)(D >>> 16);
        out[outOffset  ] = (byte)(D >>> 24);
    }


// Helper methods
//...........................................................................

    /**
     * Set encryption mode and key. Expects valid parameters only.
     */
    private final void generateSubKeys(byte[] key)
    {
        int len = key.length;
        int c   = len/4;

        int[] L = new int[c];
        for(int off=0, i=0; i<c; i++)
            L[i] = ((key[off++]&0xFF)      ) |
                   ((key[off++]&0xFF) <<  8) |
                   ((key[off++]&0xFF) << 16) |
                   ((key[off++]&0xFF) << 24);

        S[0] = P;
        for(int i=1; i<=(2*ROUNDS+3); i++)
            S[i] = S[i-1] + Q;

        int A=0, B=0, i=0, j=0, v=3*(2*ROUNDS+4);
        for(int s=1; s<=v; s++)
        {
            A = S[i] = rotl( S[i]+A+B, 3 );
            B = L[j] = rotl( L[j]+A+B, A+B );
            i = (i+1) % (2*ROUNDS+4);
            j = (j+1) % c;
        }
    }


    /**
     * Rotate left.
     *
     * @param val    value to rotate
     * @param amount rotation amount
     *
     * @return rotated value
     */
    private static int rotl(int val, int amount)
    {
        return (val << amount) | (val >>> (32-amount));
    }


    /**
     * Rotate right.
     *
     * @param val    value to rotate
     * @param amount rotation amount
     *
     * @return rotated value
     */
    private static int rotr(int val, int amount)
    {
        return (val >>> amount) | (val << (32-amount));
    }
}

/*
 * ORIGINAL LICENSE
 *
 * Jeroen C. van Gelderen wrote this file.  As long as you retain this notice
 * you can do whatever you want with this stuff. If we meet some day, and you
 * think this stuff is worth it, you can buy me a beer in return.
 *                            Jeroen C. van Gelderen <jeroen@vangelderen.org>
 */
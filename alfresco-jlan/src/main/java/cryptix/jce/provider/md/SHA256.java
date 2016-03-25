/* $Id: SHA256.java,v 1.2 2001/06/25 15:39:55 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited. All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */

package cryptix.jce.provider.md;


/**
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class SHA256 extends PaddingMD implements Cloneable {

// Constants
//...........................................................................

    /** Size (in bytes) of this hash */
    private static final int HASH_SIZE = 32;

    /** Round constants */
    private static final int K[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };


// Instance variables
//...........................................................................

    /** 8 32-bit words (interim result) */
    private final int[] context;

    /** Expanded message block buffer */
    private final int[] buffer;



// Constructors
//...........................................................................

    public SHA256() {
        super(HASH_SIZE, PaddingMD.MODE_SHA);
        this.context = new int[8];
        this.buffer  = new int[64];
        coreReset();
    }


    private SHA256(SHA256 src) {
        super(src);
        this.context = (int[])src.context.clone();
        this.buffer  = (int[])src.buffer.clone();
    }


    public Object clone() {
        return new SHA256(this);
    }


// Concreteness
//...........................................................................

    protected void coreDigest(byte[] buf, int off) {
        for( int i=0; i<context.length; i++ )
            for( int j=0; j<4 ; j++ )
                buf[off+(i * 4 + (3-j))] = (byte)(context[i] >>> (8 * j));
    }


    protected void coreReset() {
        // initial values
        context[0] = 0x6a09e667;
        context[1] = 0xbb67ae85;
        context[2] = 0x3c6ef372;
        context[3] = 0xa54ff53a;
        context[4] = 0x510e527f;
        context[5] = 0x9b05688c;
        context[6] = 0x1f83d9ab;
        context[7] = 0x5be0cd19;
    }


    protected void coreUpdate(byte[] block, int offset) {

        int[] W = buffer;

        // extract the bytes into our working buffer
        for( int i=0; i<16; i++ )
            W[i] = (block[offset++]       ) << 24 |
                   (block[offset++] & 0xFF) << 16 |
                   (block[offset++] & 0xFF) <<  8 |
                   (block[offset++] & 0xFF);

        // expand
        for( int i=16; i<64; i++ )
            W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];

        int a = context[0];
        int b = context[1];
        int c = context[2];
        int d = context[3];
        int e = context[4];
        int f = context[5];
        int g = context[6];
        int h = context[7];

        // run 64 rounds
        for( int i=0; i<64; i++ ) {
            int T1 = h + Sig1(e) + Ch(e, f, g) + K[i] + W[i];
            int T2 = Sig0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // merge
        context[0] += a;
        context[1] += b;
        context[2] += c;
        context[3] += d;
        context[4] += e;
        context[5] += f;
        context[6] += g;
        context[7] += h;
    }


    private final int Ch(int x, int y, int z) { return (x&y)^(~x&z); }

    private final int Maj(int x, int y, int z) { return (x&y)^(x&z)^(y&z); }

    private final int Sig0(int x) { return S( 2, x) ^ S(13, x) ^ S(22, x); }
    private final int Sig1(int x) { return S( 6, x) ^ S(11, x) ^ S(25, x); }
    private final int sig0(int x) { return S( 7, x) ^ S(18, x) ^ R( 3, x); }
    private final int sig1(int x) { return S(17, x) ^ S(19, x) ^ R(10, x); }

    private final int R(int off, int x) { return (x >>> off); }
    private final int S(int off, int x) { return (x>>>off) | (x<<(32-off)); }
}

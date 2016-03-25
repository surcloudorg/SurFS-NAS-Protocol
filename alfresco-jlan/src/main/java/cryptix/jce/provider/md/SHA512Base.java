/* $Id: SHA512Base.java,v 1.2 2001/06/25 15:39:55 gelderen Exp $
 *
 * Copyright (C) 2001 The Cryptix Foundation Limited. All rights reserved.
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
public abstract class SHA512Base extends PaddingMD {

// Constants
//...........................................................................

    private static final int BLOCK_SIZE = 128;

    /** Round constants */
    private static final long K[] = {
        0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL,
        0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 0x59f111f1b605d019L,
        0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L,
        0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
        0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L,
        0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L,
        0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 0x2de92c6f592b0275L,
        0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
        0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL,
        0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L,
        0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL,
        0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
        0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L,
        0x92722c851482353bL, 0xa2bfe8a14cf10364L, 0xa81a664bbc423001L,
        0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L,
        0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
        0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L,
        0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL,
        0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL,
        0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
        0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L,
        0xc67178f2e372532bL, 0xca273eceea26619cL, 0xd186b8c721c0c207L,
        0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL,
        0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
        0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL,
        0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL,
        0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };


// Instance variables
//...........................................................................

    /** 8 64-bit words (interim result) */
    private final long[] context;

    /** Expanded message block buffer */
    private final long[] buffer;


// Constructors
//...........................................................................

    public SHA512Base(int hashSize) {
        super(BLOCK_SIZE, hashSize, PaddingMD.MODE_SHA);
        this.context = new long[8];
        this.buffer  = new long[80];
        coreReset();
    }


    protected SHA512Base(SHA512Base src) {
        super(src);
        this.context = (long[])src.context.clone();
        this.buffer  = (long[])src.buffer.clone();
    }


// Abstract methods
//...........................................................................

    protected abstract void loadInitialValues(long[] context);

    protected abstract void generateDigest(long[] context, byte[] buf, int off);

// Concreteness
//...........................................................................

    protected void coreDigest(byte[] buf, int off) {
        generateDigest(context, buf, off);
    }


    protected void coreReset() {
        loadInitialValues(context);
    }


    protected void coreUpdate(byte[] block, int offset) {
        long[] W = buffer;

        // extract the bytes into our working buffer
        for( int i=0; i<16; i++ )
            W[i] = ((long)block[offset++]       ) << 56 |
                   ((long)block[offset++] & 0xFF) << 48 |
                   ((long)block[offset++] & 0xFF) << 40 |
                   ((long)block[offset++] & 0xFF) << 32 |
                   ((long)block[offset++] & 0xFF) << 24 |
                   ((long)block[offset++] & 0xFF) << 16 |
                   ((long)block[offset++] & 0xFF) <<  8 |
                   ((long)block[offset++] & 0xFF);

        // expand
        for( int i=16; i<80; i++ )
            W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];

        long a = context[0];
        long b = context[1];
        long c = context[2];
        long d = context[3];
        long e = context[4];
        long f = context[5];
        long g = context[6];
        long h = context[7];

        // run 80 rounds
        for( int i=0; i<80; i++ ) {
            long T1 = h + Sig1(e) + Ch(e, f, g) + K[i] + W[i];
            long T2 = Sig0(a) + Maj(a, b, c);
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

// Helpers
//...........................................................................

    private final long Ch(long x, long y, long z) { return (x&y)^(~x&z); }

    private final long Maj(long x, long y, long z) { return (x&y)^(x&z)^(y&z); }

    private final long Sig0(long x) { return S(28, x) ^ S(34, x) ^ S(39, x); }
    private final long Sig1(long x) { return S(14, x) ^ S(18, x) ^ S(41, x); }
    private final long sig0(long x) { return S( 1, x) ^ S( 8, x) ^ R( 7, x); }
    private final long sig1(long x) { return S(19, x) ^ S(61, x) ^ R( 6, x); }

    private final long R(int off, long x) { return (x >>> off); }
    private final long S(int off, long x) { return (x>>>off) | (x<<(64-off)); }
}

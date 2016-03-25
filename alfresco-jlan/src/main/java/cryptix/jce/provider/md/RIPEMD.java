/* $Id: RIPEMD.java,v 1.2 2001/10/10 02:51:15 gelderen Exp $
 *
 * Copyright (C) 1995-2001 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */

package cryptix.jce.provider.md;


/**
 * RIPEMD message digest algorithm as described in ISO/IEC 10118-3:1998
 * Information technology - Security techniques - Hash-functions -
 * Part 3: Dedicated hash-functions.
 *
 * RIPEMD basically is a slightly modified version of MD4 with a set of
 * parallel rounds added. It is not much more secure than MD4 and its use is
 * not recommended for anything but compatibility with legacy applications.
 *
 * http://www.iso.ch/iso/en/CatalogueDetailPage.CatalogueDetail?CSNUMBER=25428
 * http://link.springer.de/link/service/journals/00145/bibs/10n1p51.html
 * http://www.ietf.org/rfc/rfc1320.txt
 *
 * @version $Revision: 1.2 $
 * @author  Beat Meier
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class RIPEMD extends PaddingMD {

// Constants
//...........................................................................

    /** Size (in bytes) of this hash */
    private static final int HASH_SIZE = 16;



// Instance variables
//...........................................................................

    /** 4 32-bit words (interim result) */
    private int[] context = new int[4];

    /** 4 32-bit words (saved results) */
    private int[] savedContext = new int[4];

    /** 512 bits work buffer = 16 x 32-bit words */
    private int[] X = new int[16];



// Constructors
//...........................................................................

    public RIPEMD() {
        super(HASH_SIZE, PaddingMD.MODE_MD);
        coreReset();
    }

    
    private RIPEMD(RIPEMD src) {
        super(src);
        this.context      = (int[])src.context.clone();
        this.savedContext = (int[])src.savedContext.clone();
        this.X            = (int[])src.X.clone();
    }


    public Object clone() {
        return new RIPEMD(this);
    }


// Concreteness
//...........................................................................

    protected void coreDigest(byte[] buf, int off) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                buf[off+(i * 4 + j)] = (byte)(context[i] >>> (8 * j));
    }


    protected void coreReset() {
        // initial values of MD4 i.e. A, B, C, D
        // as per rfc-1320; they are low-order byte first
        context[0] = 0x67452301;
        context[1] = 0xEFCDAB89;
        context[2] = 0x98BADCFE;
        context[3] = 0x10325476;
    }


    protected void coreUpdate(byte[] block, int offset) {
        // encodes 64 bytes from input block into an
        // array of 16 32-bit entities.
        for (int i = 0; i < 16; i++)
            X[i] = (block[offset++] & 0xFF)       |
                   (block[offset++] & 0xFF) <<  8 |
                   (block[offset++] & 0xFF) << 16 |
                   (block[offset++] & 0xFF) << 24;

        int A = context[0];
        int B = context[1];
        int C = context[2];
        int D = context[3];

        // First round
        A = FF(A, B, C, D, X[ 0], 11);
        D = FF(D, A, B, C, X[ 1], 14);
        C = FF(C, D, A, B, X[ 2], 15);
        B = FF(B, C, D, A, X[ 3], 12);
        A = FF(A, B, C, D, X[ 4],  5);
        D = FF(D, A, B, C, X[ 5],  8);
        C = FF(C, D, A, B, X[ 6],  7);
        B = FF(B, C, D, A, X[ 7],  9);
        A = FF(A, B, C, D, X[ 8], 11);
        D = FF(D, A, B, C, X[ 9], 13);
        C = FF(C, D, A, B, X[10], 14);
        B = FF(B, C, D, A, X[11], 15);
        A = FF(A, B, C, D, X[12],  6);
        D = FF(D, A, B, C, X[13],  7);
        C = FF(C, D, A, B, X[14],  9);
        B = FF(B, C, D, A, X[15],  8);

        // Second round
        A = GG(A, B, C, D, X[ 7],  7);
        D = GG(D, A, B, C, X[ 4],  6);
        C = GG(C, D, A, B, X[13],  8);
        B = GG(B, C, D, A, X[ 1], 13);
        A = GG(A, B, C, D, X[10], 11);
        D = GG(D, A, B, C, X[ 6],  9);
        C = GG(C, D, A, B, X[15],  7);
        B = GG(B, C, D, A, X[ 3], 15);
        A = GG(A, B, C, D, X[12],  7);
        D = GG(D, A, B, C, X[ 0], 12);
        C = GG(C, D, A, B, X[ 9], 15);
        B = GG(B, C, D, A, X[ 5],  9);
        A = GG(A, B, C, D, X[14],  7);
        D = GG(D, A, B, C, X[ 2], 11);
        C = GG(C, D, A, B, X[11], 13);
        B = GG(B, C, D, A, X[ 8], 12);

        // Third round
        A = HH(A, B, C, D, X[ 3], 11);
        D = HH(D, A, B, C, X[10], 13);
        C = HH(C, D, A, B, X[ 2], 14);
        B = HH(B, C, D, A, X[ 4],  7);
        A = HH(A, B, C, D, X[ 9], 14);
        D = HH(D, A, B, C, X[15],  9);
        C = HH(C, D, A, B, X[ 8], 13);
        B = HH(B, C, D, A, X[ 1], 15);
        A = HH(A, B, C, D, X[14],  6);
        D = HH(D, A, B, C, X[ 7],  8);
        C = HH(C, D, A, B, X[ 0], 13);
        B = HH(B, C, D, A, X[ 6],  6);
        A = HH(A, B, C, D, X[11], 12);
        D = HH(D, A, B, C, X[13],  5);
        C = HH(C, D, A, B, X[ 5],  7);
        B = HH(B, C, D, A, X[12],  5);

        // Save results
        savedContext[0] = A;
        savedContext[1] = B;
        savedContext[2] = C;
        savedContext[3] = D;


        // Do parallel round; same init as 'normal' round

        A = context[0];
        B = context[1];
        C = context[2];
        D = context[3];

        // First parallel round
        A = FFP(A, B, C, D, X[ 0], 11);
        D = FFP(D, A, B, C, X[ 1], 14);
        C = FFP(C, D, A, B, X[ 2], 15);
        B = FFP(B, C, D, A, X[ 3], 12);
        A = FFP(A, B, C, D, X[ 4],  5);
        D = FFP(D, A, B, C, X[ 5],  8);
        C = FFP(C, D, A, B, X[ 6],  7);
        B = FFP(B, C, D, A, X[ 7],  9);
        A = FFP(A, B, C, D, X[ 8], 11);
        D = FFP(D, A, B, C, X[ 9], 13);
        C = FFP(C, D, A, B, X[10], 14);
        B = FFP(B, C, D, A, X[11], 15);
        A = FFP(A, B, C, D, X[12],  6);
        D = FFP(D, A, B, C, X[13],  7);
        C = FFP(C, D, A, B, X[14],  9);
        B = FFP(B, C, D, A, X[15],  8);

        // Second parallel round
        A = GGP(A, B, C, D, X[ 7],  7);
        D = GGP(D, A, B, C, X[ 4],  6);
        C = GGP(C, D, A, B, X[13],  8);
        B = GGP(B, C, D, A, X[ 1], 13);
        A = GGP(A, B, C, D, X[10], 11);
        D = GGP(D, A, B, C, X[ 6],  9);
        C = GGP(C, D, A, B, X[15],  7);
        B = GGP(B, C, D, A, X[ 3], 15);
        A = GGP(A, B, C, D, X[12],  7);
        D = GGP(D, A, B, C, X[ 0], 12);
        C = GGP(C, D, A, B, X[ 9], 15);
        B = GGP(B, C, D, A, X[ 5],  9);
        A = GGP(A, B, C, D, X[14],  7);
        D = GGP(D, A, B, C, X[ 2], 11);
        C = GGP(C, D, A, B, X[11], 13);
        B = GGP(B, C, D, A, X[ 8], 12);

        // Third parallel round
        A = HHP(A, B, C, D, X[ 3], 11);
        D = HHP(D, A, B, C, X[10], 13);
        C = HHP(C, D, A, B, X[ 2], 14);
        B = HHP(B, C, D, A, X[ 4],  7);
        A = HHP(A, B, C, D, X[ 9], 14);
        D = HHP(D, A, B, C, X[15],  9);
        C = HHP(C, D, A, B, X[ 8], 13);
        B = HHP(B, C, D, A, X[ 1], 15);
        A = HHP(A, B, C, D, X[14],  6);
        D = HHP(D, A, B, C, X[ 7],  8);
        C = HHP(C, D, A, B, X[ 0], 13);
        B = HHP(B, C, D, A, X[ 6],  6);
        A = HHP(A, B, C, D, X[11], 12);
        D = HHP(D, A, B, C, X[13],  5);
        C = HHP(C, D, A, B, X[ 5],  7);
        B = HHP(B, C, D, A, X[12],  5);

        // Combine results
        A += savedContext[3];
        B += savedContext[0];
        C += savedContext[1];
        D += savedContext[2];

        // Add init vector to result
        A += context[2];
        B += context[3];
        C += context[0];
        D += context[1];

        context[1] = A;
        context[2] = B;
        context[3] = C;
        context[0] = D;
    }


// The basic RIPEMD atomic functions (same as MD4!).
// ..........................................................................

    private int FF (int a, int b, int c, int d, int x, int s) {
        int t = a + ((b & c) | (~b & d)) + x;
        return t << s | t >>> (32 - s);
    }

    private int GG (int a, int b, int c, int d, int x, int s) {
        int t = a + ((b & (c | d)) | (c & d)) + x + 0x5A827999;
        return t << s | t >>> (32 - s);
    }

    private int HH (int a, int b, int c, int d, int x, int s) {
        int t = a + (b ^ c ^ d) + x + 0x6ED9EBA1;
        return t << s | t >>> (32 - s);
    }


// The additional basic parallel RIPEMD atomic functions.
// ..........................................................................

    private int FFP (int a, int b, int c, int d, int x, int s) {
        int t = a + ((b & c) | (~b & d)) + x + 0x50A28BE6;
        return t << s | t >>> (32 - s);
    }

    private int GGP (int a, int b, int c, int d, int x, int s) {
        int t = a + ((b & (c | d)) | (c & d)) + x;
        return t << s | t >>> (32 - s);
    }

    private int HHP (int a, int b, int c, int d, int x, int s) {
        int t = a + (b ^ c ^ d) + x + 0x5C4DD124;
        return t << s | t >>> (32 - s);
    }
}

/* $Id: SHA.java,v 1.7 2001/06/25 15:39:55 gelderen Exp $
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
 * SHA* core. Subclasses implement the function that expands the input block
 * to 80 32-bit words. This function differs between SHA0 and SHA1.
 *
 * @version $Revision: 1.7 $
 * @author  Jeroen C. van Gelderen
 */
/*package*/ abstract class SHA extends PaddingMD
{

// Constants
//...........................................................................

    /** Size (in bytes) of this hash */
    private static final int HASH_SIZE = 20;



// Instance variables
//...........................................................................

    /** 5 32-bit words (interim result) */
    private final int[] context;

    /** 512 bits work buffer = 80 x 32-bit words */
    private final int[] buffer;



// Constructors
//...........................................................................

    public SHA()
    {
        super(HASH_SIZE, PaddingMD.MODE_SHA);
        this.context = new int[5];
        this.buffer  = new int[80];
        coreReset();
    }


    protected SHA(SHA src) {
        super(src);
        this.context = (int[])src.context.clone();
        this.buffer  = (int[])src.buffer.clone();
    }


// Concreteness
//...........................................................................

    protected void coreDigest(byte[] buf, int off)
    {
        for( int i=0; i<context.length; i++ )
            for( int j=0; j<4 ; j++ )
                buf[off+(i * 4 + (3-j))] = (byte)(context[i] >>> (8 * j));
    }


    protected void coreReset()
    {
        // initial values
        context[0] = 0x67452301;
        context[1] = 0xefcdab89;
        context[2] = 0x98badcfe;
        context[3] = 0x10325476;
        context[4] = 0xc3d2e1f0;
    }


    protected void coreUpdate(byte[] block, int offset)
    {
        int[] W = buffer;

        // extract the bytes into our working buffer
        for( int i=0; i<16; i++ )
            W[i] = (block[offset++]       ) << 24 |
                   (block[offset++] & 0xFF) << 16 |
                   (block[offset++] & 0xFF) <<  8 |
                   (block[offset++] & 0xFF);

        expand(W);

        int A = context[0];
        int B = context[1];
        int C = context[2];
        int D = context[3];
        int E = context[4];

        E += ((A << 5)|(A >>> -5)) + f1(B, C, D) + W[0];  B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f1(A, B, C) + W[1];  A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f1(E, A, B) + W[2];  E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f1(D, E, A) + W[3];  D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f1(C, D, E) + W[4];  C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f1(B, C, D) + W[5];  B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f1(A, B, C) + W[6];  A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f1(E, A, B) + W[7];  E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f1(D, E, A) + W[8];  D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f1(C, D, E) + W[9];  C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f1(B, C, D) + W[10]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f1(A, B, C) + W[11]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f1(E, A, B) + W[12]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f1(D, E, A) + W[13]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f1(C, D, E) + W[14]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f1(B, C, D) + W[15]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f1(A, B, C) + W[16]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f1(E, A, B) + W[17]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f1(D, E, A) + W[18]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f1(C, D, E) + W[19]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f2(B, C, D) + W[20]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f2(A, B, C) + W[21]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f2(E, A, B) + W[22]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f2(D, E, A) + W[23]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f2(C, D, E) + W[24]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f2(B, C, D) + W[25]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f2(A, B, C) + W[26]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f2(E, A, B) + W[27]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f2(D, E, A) + W[28]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f2(C, D, E) + W[29]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f2(B, C, D) + W[30]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f2(A, B, C) + W[31]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f2(E, A, B) + W[32]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f2(D, E, A) + W[33]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f2(C, D, E) + W[34]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f2(B, C, D) + W[35]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f2(A, B, C) + W[36]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f2(E, A, B) + W[37]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f2(D, E, A) + W[38]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f2(C, D, E) + W[39]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f3(B, C, D) + W[40]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f3(A, B, C) + W[41]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f3(E, A, B) + W[42]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f3(D, E, A) + W[43]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f3(C, D, E) + W[44]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f3(B, C, D) + W[45]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f3(A, B, C) + W[46]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f3(E, A, B) + W[47]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f3(D, E, A) + W[48]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f3(C, D, E) + W[49]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f3(B, C, D) + W[50]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f3(A, B, C) + W[51]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f3(E, A, B) + W[52]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f3(D, E, A) + W[53]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f3(C, D, E) + W[54]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f3(B, C, D) + W[55]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f3(A, B, C) + W[56]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f3(E, A, B) + W[57]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f3(D, E, A) + W[58]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f3(C, D, E) + W[59]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f4(B, C, D) + W[60]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f4(A, B, C) + W[61]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f4(E, A, B) + W[62]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f4(D, E, A) + W[63]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f4(C, D, E) + W[64]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f4(B, C, D) + W[65]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f4(A, B, C) + W[66]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f4(E, A, B) + W[67]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f4(D, E, A) + W[68]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f4(C, D, E) + W[69]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f4(B, C, D) + W[70]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f4(A, B, C) + W[71]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f4(E, A, B) + W[72]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f4(D, E, A) + W[73]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f4(C, D, E) + W[74]; C =((C << 30)|(C >>> -30));
        E += ((A << 5)|(A >>> -5)) + f4(B, C, D) + W[75]; B =((B << 30)|(B >>> -30));
        D += ((E << 5)|(E >>> -5)) + f4(A, B, C) + W[76]; A =((A << 30)|(A >>> -30));
        C += ((D << 5)|(D >>> -5)) + f4(E, A, B) + W[77]; E =((E << 30)|(E >>> -30));
        B += ((C << 5)|(C >>> -5)) + f4(D, E, A) + W[78]; D =((D << 30)|(D >>> -30));
        A += ((B << 5)|(B >>> -5)) + f4(C, D, E) + W[79]; C =((C << 30)|(C >>> -30));

        context[0] += A;
        context[1] += B;
        context[2] += C;
        context[3] += D;
        context[4] += E;
    }

    private static int f1(int a, int b, int c)
    {
        return (c^(a&(b^c))) + 0x5A827999;
    }

    private static int f2(int a, int b, int c)
    {
        return (a^b^c) + 0x6ED9EBA1;
    }

    private static int f3(int a, int b, int c)
    {
        return ((a&b)|(c&(a|b))) + 0x8F1BBCDC;
    }

    private static int f4(int a, int b, int c)
    {
        return (a^b^c) + 0xCA62C1D6;
    }


// Abstract methods
//...........................................................................

    protected abstract void expand(int[] W);
}
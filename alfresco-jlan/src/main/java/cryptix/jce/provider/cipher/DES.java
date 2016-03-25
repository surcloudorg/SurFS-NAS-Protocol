/* $Id: DES.java,v 1.11 2001/08/06 21:22:55 edwin Exp $
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


import cryptix.jce.provider.key.*;
import java.security.InvalidKeyException;
import java.security.Key;


/**
 * DES is a block cipher with an 8 byte block size. The key length
 * is 8 bytes, but only 56 bits are used as the parity bit in each
 * byte is ignored.
 * <p>
 * This algorithm has been seriously analysed over the last 30 years,
 * and no significant weaknesses have been reported. Its only known
 * flaw is that the key length of 56 bits makes it relatively easy to
 * brute-force it.
 * <p>
 * To overcome this near-fatal flaw, it is recommended that DES be
 * used in Triple DES mode. The JCA algorithm name for the recommended
 * form of Triple DES is "DES-EDE3".
 * <p>
 * DES was invented by IBM and first released in 1976. The algorithm is
 * freely usable for both single and triple encryption.
 * <p>
 * References:<br>
 * <ul>
 * <li>"Chapter 12 Data Encryption Standard,"
 *     Applied Cryptography, 2nd edition,
 *     Bruce Schneier, John Wiley &amp; Sons, 1996.</li>
 *
 * <li>NIST FIPS PUB 46-2 (supercedes FIPS PUB 46-1),
 *     "Data Encryption Standard",
 *     U.S. Department of Commerce, December 1993.<br>
 *     <a href="http://www.itl.nist.gov/fipspubs/fip46-2.htm">
 *     http://www.itl.nist.gov/fipspubs/fip46-2.htm</a></li>
 * </ul>
 *
 * @version $Revision: 1.11 $
 * @author Systemics Ltd
 * @author David Hopwood
 * @author Eric Young
 * @author Geoffrey Keating
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @author John F. Dumas          (jdumas@zgs.com)
 * @author Raif S. Naffah         (raif@cryptix.org)
 */
public final class DES
extends BlockCipher
{

// Static variables and constants
// ...................................................................

    private static final int
        ROUNDS         = 16,  // number of encryption/decryption rounds
        BLOCK_SIZE     =  8,  // DES block size in bytes
        KEY_LENGTH     =  8,  // DES key length in bytes
        ALT_KEY_LENGTH =  7,  // Alternate DES key length in bytes
        INTERNAL_KEY_LENGTH = 2 * ROUNDS; // number of elements in key schedule


    /** Table for PC2 permutations in key schedule computation. */
    private static final int[] SKB = new int[8 * 64];


    /** Table for S-boxes and permutations, used in encrypt_base. */
    private static final int SP_TRANS[] = new int[8 * 64];


    /** Build the SKB and SP_TRANS tables */
    static 
    {
        // build the SKB table
        // represent the bit number that each permutated bit is derived from
        // according to FIPS-46
        String cd =
            "D]PKESYM`UBJ\\@RXA`I[T`HC`LZQ"+"\\PB]TL`[C`JQ@Y`HSXDUIZRAM`EK";
        int j, s, bit;
        int count = 0;
        int offset = 0;
        for (int i = 0; i < cd.length(); i++) 
        {
            s = cd.charAt(i) - '@';
            if (s != 32) 
            {
                bit = 1 << count++;
                for (j = 0; j < 64; j++)
                    if ((bit & j) != 0) SKB[offset + j] |= 1 << s;
                if (count == 6) 
                {
                    offset += 64;
                    count = 0;
                }
            }
        }


        // build the SP_TRANS table
        // I'd _really_ like to just say 'SP_TRANS = { ... }', but
        // that would be terribly inefficient (code size + time).
        // Instead we use a compressed representation --GK
        String spt =
            "g3H821:80:H03BA0@N1290BAA88::3112aIH8:8282@0@AH0:1W3A8P810@22;22"+
            "A18^@9H9@129:<8@822`?:@0@8PH2H81A19:G1@03403A0B1;:0@1g192:@919AA"+
            "0A109:W21492H@0051919811:215011139883942N8::3112A2:31981jM118::A"+
            "101@I88:1aN0<@030128:X;811`920:;H0310D1033@W980:8A4@804A3803o1A2"+
            "021B2:@1AH023GA:8:@81@@12092B:098042P@:0:A0HA9>1;289:@1804:40Ph="+
            "1:H0I0HP0408024bC9P8@I808A;@0@0PnH0::8:19J@818:@iF0398:8A9H0<13@"+
            "001@11<8;@82B01P0a2989B:0AY0912889bD0A1@B1A0A0AB033O91182440A9P8"+
            "@I80n@1I03@1J828212A`A8:12B1@19A9@9@8^B:0@H00<82AB030bB840821Q:8"+
            "310A302102::A1::20A1;8"; // OK, try to type _that_!
            // [526 chars, 3156 bits]
        // The theory is that each bit position in each int of SP_TRANS is
        // set in exactly 32 entries. We keep track of set bits.
        offset = 0;
        int k, c, param;
        for (int i = 0; i < 32; i++) // each bit position
        { 
            k = -1; // pretend the -1th bit was set
            bit = 1 << i;
            for (j = 0; j < 32; j++) // each set bit
            { 
                // Each character consists of two three-bit values:
                c = spt.charAt(offset >> 1) - '0' >> (offset & 1) * 3 & 7;
                offset++;
                if (c < 5) 
                {
                    // values 0...4 indicate a set bit 1...5 positions
                    // from the previous set bit
                    k += c + 1;
                    SP_TRANS[k] |= bit;
                    continue;
                }
                // other values take at least an additional parameter:
                // the next value in the sequence.
                param = spt.charAt(offset >> 1) - '0' >> (offset & 1) * 3 & 7;
                offset++;
                if (c == 5) 
                {
                    // indicates a bit set param+6 positions from
                    // the previous set bit
                    k += param + 6;
                    SP_TRANS[k] |= bit;
                } 
                else if (c == 6) 
                {
                    // indicates a bit set (param * 64) + 1 positions
                    // from the previous set bit
                    k += (param << 6) + 1;
                    SP_TRANS[k] |= bit;
                } 
                else 
                {
                    // indicates that we should skip (param * 64) positions,
                    // then process the next value which will be in the range
                    // 0...4.
                    k += param << 6;
                    j--;
                }
            }
        }
    }



// Instance variables
// ...................................................................

    /** The internal key schedule */
    private int[] sKey = new int[INTERNAL_KEY_LENGTH];



// Constructor, ...
// ...................................................................

    public DES() 
    {
        super("DES",BLOCK_SIZE);
    }



// BPI methods
// ...................................................................

    protected void coreInit(Key key, boolean decrypt)
    throws InvalidKeyException
    {
        byte[] userkey = key.getEncoded();
        if (userkey == null)
            throw new InvalidKeyException("Null user key");

        if (userkey.length == ALT_KEY_LENGTH) {

            byte[] temp = new byte[KEY_LENGTH];

            temp[0] = (byte)(                     userkey[0]                );
            temp[1] = (byte)( userkey[0] << 7  |  userkey[1] >>> 1  &  0x7f );
            temp[2] = (byte)( userkey[1] << 6  |  userkey[2] >>> 2  &  0x3f );
            temp[3] = (byte)( userkey[2] << 5  |  userkey[3] >>> 3  &  0x1f );
            temp[4] = (byte)( userkey[3] << 4  |  userkey[4] >>> 4  &  0x0f );
            temp[5] = (byte)( userkey[4] << 3  |  userkey[5] >>> 5  &  0x07 );
            temp[6] = (byte)( userkey[5] << 2  |  userkey[6] >>> 6  &  0x03 );
            temp[7] = (byte)( userkey[6] << 1                               );

            userkey = temp;
        }

        if (userkey.length != KEY_LENGTH)
            throw new InvalidKeyException("Invalid user key length");

        int i = 0;
        int c = (userkey[i++] & 0xFF)       |
                (userkey[i++] & 0xFF) <<  8 |
                (userkey[i++] & 0xFF) << 16 |
                (userkey[i++]       ) << 24;
        int d = (userkey[i++] & 0xFF)       |
                (userkey[i++] & 0xFF) <<  8 |
                (userkey[i++] & 0xFF) << 16 |
                (userkey[i  ]       ) << 24;

        int t = ((d >>> 4) ^ c) & 0x0F0F0F0F;
        c ^= t;
        d ^= t << 4;
        t = ((c << 18) ^ c) & 0xCCCC0000;
        c ^= t ^ t >>> 18;
        t = ((d << 18) ^ d) & 0xCCCC0000;
        d ^= t ^ t >>> 18;
        t = ((d >>> 1) ^ c) & 0x55555555;
        c ^= t;
        d ^= t << 1;
        t = ((c >>> 8) ^ d) & 0x00FF00FF;
        d ^= t;
        c ^= t << 8;
        t = ((d >>> 1) ^ c) & 0x55555555;
        c ^= t;
        d ^= t << 1;

        d = (d & 0x000000FF) <<  16 |
            (d & 0x0000FF00)        |
            (d & 0x00FF0000) >>> 16 |
            (c & 0xF0000000) >>>  4;
        c &= 0x0FFFFFFF;

        int s;
        int j = 0;

        for (i = 0; i < ROUNDS; i++) 
        {
            if ((0x7EFC >> i & 1) == 1) 
            {
                c = (c >>> 2 | c << 26) & 0x0FFFFFFF;
                d = (d >>> 2 | d << 26) & 0x0FFFFFFF;
            } 
            else 
            {
                c = (c >>> 1 | c << 27) & 0x0FFFFFFF;
                d = (d >>> 1 | d << 27) & 0x0FFFFFFF;
            }
            s = SKB[           c         & 0x3F                        ] |
                SKB[0x040 | (((c >>>  6) & 0x03) | ((c >>>  7) & 0x3C))] |
                SKB[0x080 | (((c >>> 13) & 0x0F) | ((c >>> 14) & 0x30))] |
                SKB[0x0C0 | (((c >>> 20) & 0x01) | ((c >>> 21) & 0x06)
                                                 | ((c >>> 22) & 0x38))];
            t = SKB[0x100 | ( d         & 0x3F                      )] |
                SKB[0x140 | (((d >>>  7) & 0x03) | ((d >>>  8) & 0x3c))] |
                SKB[0x180 | ((d >>> 15) & 0x3F                      )] |
                SKB[0x1C0 | (((d >>> 21) & 0x0F) | ((d >>> 22) & 0x30))];

            sKey[j++] = t <<  16 | (s & 0x0000FFFF);
            s         = s >>> 16 | (t & 0xFFFF0000);
            sKey[j++] = s <<   4 |  s >>> 28;
        }


        // Reverse the subkeys if we're decrypting
        // Best illustrated by example: 1 2 3 4 5 6 7 8  ->  7 8 5 6 3 4 1 2
        if(decrypt) 
        {
            for(i=0; i<16; i++)
            {
                j = 30 - i + ( i%2 * 2 );
                t = sKey[i];  sKey[i] = sKey[j];  sKey[j] = t;
            }
        }
    }



    /**
     * Perform a DES encryption or decryption operation of a single block.
     */
    protected void coreCrypt(byte[] in, int inOffset, byte[] out, int outOffset)
    {
        int L = (in[inOffset++] & 0xFF)       |
                (in[inOffset++] & 0xFF) <<  8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset++]       ) << 24;
        int R = (in[inOffset++] & 0xFF)       |
                (in[inOffset++] & 0xFF) <<  8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset  ]       ) << 24;

        // Initial permutation
        int t = ((R >>> 4) ^ L) & 0x0F0F0F0F;
        L ^= t;
        R ^= t << 4;
        t = ((L >>> 16) ^ R) & 0x0000FFFF;
        R ^= t;
        L ^= t << 16;
        t = ((R >>> 2) ^ L) & 0x33333333;
        L ^= t;
        R ^= t << 2;
        t = ((L >>> 8) ^ R) & 0x00FF00FF;
        R ^= t;
        L ^= t << 8;
        t = ((R >>> 1) ^ L) & 0x55555555;
        L ^= t;
        R ^= t << 1;


        // look! we fit all four variables (plus the class itself)
        // into short byte-codes!
        int u = R << 1 | R >>> 31;
        R = L << 1 | L >>> 31;
        L = u;

        for (int i = 0; i < INTERNAL_KEY_LENGTH;) 
        {
            u = R ^ sKey[i++];
            t = R ^ sKey[i++];
            t = t >>> 4 | t << 28;
            L ^= (SP_TRANS[0x040 | ( t         & 0x3F)] |
                  SP_TRANS[0x0C0 | ((t >>>  8) & 0x3F)] |
                  SP_TRANS[0x140 | ((t >>> 16) & 0x3F)] |
                  SP_TRANS[0x1C0 | ((t >>> 24) & 0x3F)] |
                  SP_TRANS[          u         & 0x3F ] |
                  SP_TRANS[0x080 | ((u >>>  8) & 0x3F)] |
                  SP_TRANS[0x100 | ((u >>> 16) & 0x3F)] |
                  SP_TRANS[0x180 | ((u >>> 24) & 0x3F)]);

            u = L ^ sKey[i++];
            t = L ^ sKey[i++];
            t = t >>> 4 | t << 28;
            R ^= (SP_TRANS[0x040 | ( t         & 0x3F)] |
                  SP_TRANS[0x0C0 | ((t >>>  8) & 0x3F)] |
                  SP_TRANS[0x140 | ((t >>> 16) & 0x3F)] |
                  SP_TRANS[0x1C0 | ((t >>> 24) & 0x3F)] |
                  SP_TRANS[          u         & 0x3F ] |
                  SP_TRANS[0x080 | ((u >>>  8) & 0x3F)] |
                  SP_TRANS[0x100 | ((u >>> 16) & 0x3F)] |
                  SP_TRANS[0x180 | ((u >>> 24) & 0x3F)]);
        }
        R = R >>> 1 | R << 31;
        L = L >>> 1 | L << 31;


        // Final permutation
        t = (R >>> 1 ^ L) & 0x55555555;
        L ^= t;
        R ^= t << 1;
        t = (L >>> 8 ^ R) & 0x00FF00FF;
        R ^= t;
        L ^= t << 8;
        t = (R >>> 2 ^ L) & 0x33333333;
        L ^= t;
        R ^= t << 2;
        t = (L >>> 16 ^ R) & 0x0000FFFF;
        R ^= t;
        L ^= t << 16;
        t = (R >>> 4 ^ L) & 0x0F0F0F0F;

        L ^= t;
        R ^= (t << 4);

        out[outOffset++] = (byte)(L      );
        out[outOffset++] = (byte)(L >>  8);
        out[outOffset++] = (byte)(L >> 16);
        out[outOffset++] = (byte)(L >> 24);
        out[outOffset++] = (byte)(R      );
        out[outOffset++] = (byte)(R >>  8);
        out[outOffset++] = (byte)(R >> 16);
        out[outOffset  ] = (byte)(R >> 24);
    }
}

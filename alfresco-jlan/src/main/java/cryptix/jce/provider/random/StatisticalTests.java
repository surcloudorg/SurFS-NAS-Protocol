/* $Id: StatisticalTests.java,v 1.2 2000/07/29 00:30:25 gelderen Exp $
 *
 * Copyright (C) 1999-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.random;


/**
 * Couple of statistical tests for verifying (P)RNG output as defined in 
 * FIPS 140-1.
 *
 * <p>See <a href="http://www.itl.nist.gov/fipspubs/fip140-1.htm">
 * http://www.itl.nist.gov/fipspubs/fip140-1.htm</a></p>
 *
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
/*package*/ final class StatisticalTests
{
    /**
     * Static methods only.
     */
    private StatisticalTests() {}


    /** Number of one bits in a four-bit nibble */
    private static final int[] ONE_COUNT = {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4
    };


    /**
     * Use some basic tests and report whether the data looks random.
     *
     * @param  data 2500 bytes (20,000 bits) of data to be tested
     * @return true if the data 'looks random'
     * @throws IllegalArgumentException when not 2500 bytes are input
     */
    public static boolean looksRandom(byte[] data) {
        return testMonobit(data) && testPoker(data);
    }


    /**
     * Monobit test as defined in FIPS 140-1.
     *
     * @param  data 2500 bytes (20,000 bits) of data to be tested
     * @return true if the data passes the test, false otherwise
     * @throws IllegalArgumentException on illegal input data
     */
    public static boolean testMonobit(byte[] data) 
    {
        if( data.length != 2500 )
            throw new IllegalArgumentException("2500 bytes expected");
            
        int total = 0;
        for(int i=0; i<2500; i++) {
            int hi = ONE_COUNT[ (data[i]>>4) & 0xF ];
            int lo = ONE_COUNT[ (data[i]   ) & 0xF ];
            total += hi + lo;
        }
        
        return (9654 < total) && (total < 10346);
    }
    

    /**
     * Poker test as defined in FIPS 140-1.
     *
     * @param  data 2500 bytes (20,000 bits) of data to be tested
     * @return true if the data passes the test, false otherwise
     * @throws IllegalArgumentException on illegal input data
     */    
    public static boolean testPoker(byte[] data) 
    {
        if( data.length != 2500 )
            throw new IllegalArgumentException("2500 bytes expected");
                    
        int[] b = new int[16];
        
        for(int i=0; i<data.length; i++) {
            b[ (data[i]    ) & 0xF ]++;
            b[ (data[i]>>>4) & 0xF ]++;
        }
        
        int sigma = 0;
        for(int i=0; i<16; i++)
            sigma += b[i]*b[i];

        float res = (16.0f*sigma)/5000.0f - 5000.0f;
        
        return (1.03f < res) && (res < 57.4f);
    }
}

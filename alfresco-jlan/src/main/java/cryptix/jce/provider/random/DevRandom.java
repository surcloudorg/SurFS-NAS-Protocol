/* $Id: DevRandom.java,v 1.1 2000/07/29 02:17:42 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited. All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.random;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.SecureRandomSpi;


/**
 * SecureRandomSpi that gets it's random bytes from the /dev/urandom PRNG
 * on systems that support it. This Spi will only enable itself when it
 * can read from /dev/urandom <em>and</em> the first 2500 bytes extracted
 * from /dev/urandom pass some basic statistical tests.
 *
 * It's mandatory to check the result of the isAvailable() method before 
 * calling the constructor.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class DevRandom extends SecureRandomSpi {

// Static variables, method and initializer
//............................................................................

    /** Name of the PRNG file. */
    private static final String RANDOM_DEV_NAME = "/dev/urandom";


    /** File representing the randomness device. */
    private static final File RANDOM_DEV = new File(RANDOM_DEV_NAME);


    /**
     * Randomness file input stream. A setting of null denotes that
     * this Spi is not available.
     */
    private static FileInputStream randomStream = null;


    /**
     * Open /dev/urandom and check whether the first 2500 bytes (20000 bits)
     * look random. If they don't look random, disable this Spi.
     */
    static {
        try {
            randomStream = new FileInputStream(RANDOM_DEV);

            byte[] test_bytes = new byte[2500];
            getRandomBytes(test_bytes);
            if( !StatisticalTests.looksRandom(test_bytes) ) {
                System.out.println(
                    "CryptixRandom Provider:" +
                    "Output of " + RANDOM_DEV_NAME + " doesn't look random, " +
                    "this may indicate a serious security problem!");

                randomStream.close();
                randomStream = null;
            }
        } catch(IOException e) {
            randomStream = null;
        }

        // randomStream == null means this one is disabled
    }


    /**
     * Fill the given array with random bytes read from randomStream.
     *
     * @throws IOException
     *         Propagated from the underlying FileInputStream.
     */
    private static void getRandomBytes(byte[] bytes) throws IOException {
        int count;
        int offset = 0;
        int todo   = bytes.length;
        while( todo > 0 ) {
            synchronized(randomStream) {
                if( (count = randomStream.read(bytes, offset, todo)) == -1 )
                    throw new IOException("EOF");
            }
            offset += count;
            todo   -= count;
        }
    }


// Constructor
//............................................................................

    /**
     * Construct a new Spi that uses /dev/urandom as PRNG. Only call this
     * when isAvailable() returns true.
     *
     * @throws InternalError
     *         When called when isAvailable() returns false
     *         (i.e. the static initializer failed to open the device).
     */
    public DevRandom() {
        if(randomStream == null)
            throw new InternalError("randomStream == null");
    }


// SecureRandomSpi implementation
//............................................................................

    /**
     * Doesn't do anything in this Spi.
     */
    protected void engineSetSeed(byte[] seed) {
        // user seeds are ignored
        // XXX: possibly, maybe try and write given entropy to /dev/random?
    }


    /**
     * Fill the given array with random bytes read from /dev/urandom.
     *
     * @throws RuntimeException
     *         In case reading /dev/urandom causes an exception or EOF.
     */
    protected void engineNextBytes(byte[] bytes) {
        try {
            getRandomBytes(bytes);
        } catch(IOException e) {
            throw new RuntimeException(
                "Cannot read from randomness device: " + e);
        }
    }


    /**
     * Return a seed. Calls upon engineNextBytes().
     *
     * @throws RuntimeException
     *         In case reading /dev/urandom causes an exception or EOF.
     */
    protected byte[] engineGenerateSeed(int numBytes) {
        byte[] seed = new byte[numBytes];
        this.engineNextBytes(seed);
        return seed;
    }


// Cryptix provider-internal interface
//............................................................................

    /**
     * Whether this Spi is available (/dev/urandom readable and looking
     * random). Used to determine whether registration allowed.
     */
    public static boolean isAvailable() {
        return randomStream != null;
    }
}

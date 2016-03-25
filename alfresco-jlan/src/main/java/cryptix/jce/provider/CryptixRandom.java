/* $Id: CryptixRandom.java,v 1.1 2000/07/29 02:19:27 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited. All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider;


import java.security.Provider;

import cryptix.jce.provider.random.DevRandom;


/**
 * The Cryptix JCE Randomness Provider.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class CryptixRandom extends Provider {

// Static variables and constants
//...........................................................................

    private static final String
        NAME    = "CryptixRandom",
        INFO    = "Cryptix JCE Randomness Provider";
    private static final double
        VERSION = 1.2;


// Constructor
//...........................................................................

    public CryptixRandom() {

        super(NAME, VERSION, INFO);

        if( DevRandom.isAvailable() )
            put("SecureRandom.DevRandom", 
                            "cryptix.jce.provider.random.DevRandom");
    }
}

/* $Id: AsnNull.java,v 1.1 2000/08/25 01:04:36 gelderen Exp $
 *
 * Copyright (c) 2000 The Cryptix Foundation Limited. All rights reserved.
 */

package cryptix.jce.provider.asn;


import java.io.IOException;


/**
 * Immutable object representing an ASN.1 NULL value.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class AsnNull extends AsnObject {

// Ctors
//............................................................................

    public AsnNull(AsnInputStream is) throws IOException {
        super(AsnObject.TAG_NULL);
        int len = is.readLength();
    }


    public AsnNull() {
        super(AsnObject.TAG_NULL);
    }


//............................................................................

    protected void encodePayload(AsnOutputStream os) throws IOException {
        // no payload
    }


    protected int getEncodedLengthOfPayload(AsnOutputStream os) {
        return 0;
    }


    public String toString(String indent) {
        return indent + "NULL";
    }
}

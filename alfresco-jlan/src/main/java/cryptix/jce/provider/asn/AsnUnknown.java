/* $Id: AsnUnknown.java,v 1.1 2000/08/25 01:04:36 gelderen Exp $
 *
 * Copyright (c) 2000 The Cryptix Foundation Limited. All rights reserved.
 */

package cryptix.jce.provider.asn;


import java.io.IOException;


/**
 * Immutable object representing an unknown ASN.1 type.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class AsnUnknown extends AsnObject
{
    private final byte[] data;


    public AsnUnknown(byte tag, AsnInputStream is) throws IOException {
        super(tag);
        int len = is.readLength();
        this.data = is.readBytes(len);
    }


    /** Write out payload. */
    protected void encodePayload(AsnOutputStream os) throws IOException {
        os.writeBytes(data);
    }


    protected int getEncodedLengthOfPayload(AsnOutputStream os) {
        return data.length;
    }


    public String toString(String indent) {
        return indent + 
               "<unknown> (tag: " + this.getTag() +
               ", len: " + this.data.length +")";
    }
}

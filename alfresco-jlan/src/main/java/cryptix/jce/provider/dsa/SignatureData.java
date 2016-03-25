/* $Id: SignatureData.java,v 1.5 2000/02/19 03:01:35 gelderen Exp $
 *
 * Copyright (C) 1995-1999 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */

package cryptix.jce.provider.dsa;


import java.math.BigInteger;
import java.security.SignatureException;


/**
 * Reads and writes DER encoded DSA signatures.
 *
 * <p>DSA signatures are encoded as a DER sequence
 * of two ASN.1 INTEGER values like this:
 * <pre>SEQUENCE { r INTEGER; s INTEGER }</pre>
 *
 * @author Edwin Woudt (edwin@cryptix.org)
 */
class SignatureData
{
    private BigInteger r, s;


    /**
     * Initializes the parser with a DER sequence.
     *
     * Use getR() and getS() to get the decoded numbers.
     *
     * @throws SignatureException if data is not correctly formatted
     */
    public SignatureData(byte[] data)
    throws SignatureException
    {
        try
        {
            int i=0;

            if ( (data[i++] != 0x30) || (data[i++] != data.length-2) ||
                 (data[i++] != 0x02) )
                throw new SignatureException("Corrupted signature data");

            byte len=data[i++];

            if (len > 21)
                throw new SignatureException("Corrupted signature data");

            byte[] rdata=new byte[len];
            for (int j=0; j<len; j++)
                rdata[j] = data[i++];

            if (data[i++] != 0x02)
                throw new SignatureException("Corrupted signature data");

            len=data[i++];

            if (len > 21)
                throw new SignatureException("Corrupted signature data");

            byte[] sdata=new byte[len];
            for (int j=0; j<len; j++)
                sdata[j] = data[i++];

            r = new BigInteger(rdata);
            s = new BigInteger(sdata);

            if ((i != data.length) || (r.signum() != 1) || (s.signum() != 1))
                throw new SignatureException("Corrupted signature data");
        }
        catch(NullPointerException npe)
        {
            throw new SignatureException("Corrupted signature data");
        }
        catch(ArrayIndexOutOfBoundsException aioobe)
        {
            throw new SignatureException("Corrupted signature data");
        }
    }


    /**
     * Initializes the parser with the two numbers r and s.
     *
     * Use getData() to get the encoded DER sequence.
     *
     * @throws SignatureException if r or s is null
     */
    public SignatureData(BigInteger r, BigInteger s)
    throws SignatureException
    {
        if ((r == null) || (s == null))
            throw new SignatureException("Invalid signature");

        if ((r.signum() != 1) || (s.signum() != 1))
            throw new SignatureException("Invalid signature");

        this.r = r;
        this.s = s;
    }


    /** Returns the decoded r */
    public BigInteger getR() { return r; }


    /** Returns the decoded s */
    public BigInteger getS() { return s; }


    /**
     * Returns the encoded DER sequence
     */
    public byte[] getData()
    {
        byte[] rdata = r.toByteArray();
        byte[] sdata = s.toByteArray();
        byte[] data = new byte[6 + rdata.length + sdata.length];
        int i=0;
        data[i++] = 0x30;
        data[i++] = (byte)(data.length-2);
        data[i++] = 0x02;
        data[i++] = (byte)(rdata.length);

        for (int j=0; j<rdata.length; j++)
            data[i++] = rdata[j];

        data[i++] = 0x02;
        data[i++] = (byte)(sdata.length);

        for (int j=0; j<sdata.length; j++)
            data[i++] = sdata[j];

        return data;
    }

}

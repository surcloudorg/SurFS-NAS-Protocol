/* $Id: MPIOutputStream.java,v 1.3 2000/01/20 14:59:38 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.util;


import java.math.BigInteger;
import java.io.IOException;
import java.io.OutputStream;


/**
 * @version $Revision: 1.3 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class MPIOutputStream
{

// Instance variables
//...........................................................................

    private final OutputStream os;
    

// Constructors
//...........................................................................

    public MPIOutputStream(OutputStream os)
    {
        this.os = os;
    }


//...........................................................................
    
    public void close()
    throws IOException
    {
        this.os.close();
    }

    
    public void flush()
    throws IOException
    {
        this.os.flush();
    }
    
    
    public void write(BigInteger bi)
    throws IOException
    {
        byte[] tmp = bi.toByteArray();
        
        // minimum length of tmp is 4 bytes so this is safe
        short upperTwo = (short)( (tmp[0] << 8) | tmp[1] );
        if( upperTwo !=0 )
            throw new IOException("bi: unsupported value");
            
        this.os.write(tmp, 2, tmp.length-2);
    }
}

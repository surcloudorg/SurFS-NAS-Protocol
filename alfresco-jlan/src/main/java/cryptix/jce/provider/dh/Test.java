/* $Id: Test.java,v 1.3 2000/07/28 20:09:41 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.dh;


import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;


/**
 * @version $Revision: 1.3 $
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class Test
{
    public static void main(String[] argv)
    {
        while(true)
            work();
    }
    
    public static void work()
    {
        Security.addProvider(new cryptix.jce.provider.CryptixCrypto());
        
        try
        {
            KeyPairGenerator kpg1 = KeyPairGenerator.getInstance("DH");
            kpg1.initialize(1536);
            KeyPair pair1 = kpg1.generateKeyPair();

            KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("DH");
            kpg2.initialize(1536);
            KeyPair pair2 = kpg2.generateKeyPair();
            
            KeyAgreement ka1 = KeyAgreement.getInstance("DH");
            ka1.init( pair1.getPrivate() );
            ka1.doPhase( pair2.getPublic(), true );
            byte[] master1 = ka1.generateSecret();

            KeyAgreement ka2 = KeyAgreement.getInstance("DH");
            ka2.init( pair2.getPrivate() );
            ka2.doPhase( pair1.getPublic(), true );
            byte[] master2 = ka2.generateSecret();
            
            if( master1.length != master2.length )
                throw new RuntimeException();
                
            for( int i=0; i<master1.length; i++ )
            {
                if( master1[i] != master2[i] )
                    throw new RuntimeException();
            }
            System.out.println();
            
            System.out.println("master1.length: " + master1.length);
            if(master1.length != 192)
                throw new RuntimeException();
            
            System.out.println("master1: " + 
                    new BigInteger(1, master1).toString(16) );
                    
            System.out.println("Done");
        }
        catch(Throwable t)
        {
            t.printStackTrace();
        }
    }
}


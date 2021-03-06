/*
 * Copyright (C) 2006-2007 Alfresco Software Limited.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

 * As a special exception to the terms and conditions of version 2.0 of 
 * the GPL, you may redistribute this Program in connection with Free/Libre 
 * and Open Source Software ("FLOSS") applications as described in Alfresco's 
 * FLOSS exception.  You should have recieved a copy of the text describing 
 * the FLOSS exception, and it is also available here: 
 * http://www.alfresco.com/legal/licensing"
 */
/***************************************************************************
 *
 * Copyright (C) 2016 SurCloud.
 *
 * This file was modified by SurCloud and is part of JLAN for SurFS, you
 * can redistribute and/or modify it under the same license terms as above.
 *
 * JLAN for SurFS is likewise distributed WITHOUT ANY WARRANTY.
 */
package org.alfresco.jlan.smb.server;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.channels.ServerSocketChannel;

import org.alfresco.jlan.debug.Debug;

/**
 * Session Socket Handler Abstract Class
 *
 * @author gkspencer
 */
public abstract class SessionSocketHandler implements Runnable {

    //	Define the listen backlog for the server socket
    protected static final int LISTEN_BACKLOG = 10;

    //	Server that the socket handler is associated with
    private SMBServer m_server;

    //	Address/post to use
    private int m_port;
    private InetAddress m_bindAddr;

    //	Server socket
    private ServerSocketChannel m_srvSock;

    //	Debug output enable
    private boolean m_debug;

    //	Socket handler thread shutdown flag
    private boolean m_shutdown;

    //	Session socket handler name
    private String m_name;

    //	Session id
    private static int m_sessId;

    /**
     * Class constructor
     *
     * @param name String
     * @param srv SMBServer
     * @param port int
     * @param bindAddr InetAddress
     * @param debug boolean
     */
    public SessionSocketHandler(String name, SMBServer srv, int port, InetAddress bindAddr, boolean debug) {
        m_name = name;
        m_server = srv;
        m_port = port;
        m_bindAddr = bindAddr;
        m_debug = debug;
    }

    /**
     * Class constructor
     *
     * @param name String
     * @param srv SMBServer
     * @param debug boolean
     */
    public SessionSocketHandler(String name, SMBServer srv, boolean debug) {
        m_name = name;
        m_server = srv;
        m_debug = debug;
    }

    /**
     * Return the handler name
     *
     * @return String
     */
    public final String getName() {
        return m_name;
    }

    /**
     * Return the server
     *
     * @return SMBServer
     */
    protected final SMBServer getServer() {
        return m_server;
    }

    /**
     * Return the port
     *
     * @return int
     */
    protected final int getPort() {
        return m_port;
    }

    /**
     * Determine if the socket handler should bind to a particular address
     *
     * @return boolean
     */
    protected final boolean hasBindAddress() {
        return m_bindAddr != null ? true : false;
    }

    /**
     * Return the bind address
     *
     * return InetAddress
     */
    protected final InetAddress getBindAddress() {
        return m_bindAddr;
    }

    /**
     * Return the next session id
     *
     * @return int
     */
    protected final synchronized int getNextSessionId() {
        return m_sessId++;
    }

    /**
     * Determine if debug output is enabled
     *
     * @return boolean
     */
    protected final boolean hasDebug() {
        return m_debug;
    }

    /**
     * Return the server socket
     *
     * @return ServerSocket
     */
    protected final ServerSocketChannel getSocket() {
        return m_srvSock;
    }

    /**
     * Set the server socket
     *
     * @param sock ServerSocket
     */
    protected final void setSocket(ServerSocketChannel sock) {
        m_srvSock = sock;
    }

    /**
     * Determine if the shutdown flag is set
     *
     * @return boolean
     */
    protected final boolean hasShutdown() {
        return m_shutdown;
    }

    /**
     * Clear the shutdown request flag
     */
    protected final void clearShutdown() {
        m_shutdown = false;
    }

    /**
     * Request the socket handler to shutdown
     */
    public void shutdownRequest() {

        //	Indicate that the server is closing
        m_shutdown = true;

        try {

            //	Close the server socket so that any pending receive is cancelled
            if (m_srvSock != null) {
                m_srvSock.close();
            }
        } catch (SocketException ex) {
        } catch (Exception ex) {
        }
    }

    /**
     * Initialize the session socket handler
     *
     * @exception Exception
     */
    public void initialize()
            throws Exception {

        //	Check if the server should bind to a particular local address, or all local addresses
        ServerSocketChannel srvSock = ServerSocketChannel.open();
        srvSock.configureBlocking(true);
        srvSock.socket().setReuseAddress(true);
        if (hasBindAddress()) {
            srvSock.socket().bind(new InetSocketAddress(getBindAddress(), getPort()));
            //srvSock = new ServerSocket(getPort(), LISTEN_BACKLOG, getBindAddress());
        } else {
            srvSock.socket().bind(new InetSocketAddress(getPort()));
            //srvSock = new ServerSocket(getPort(), LISTEN_BACKLOG);
        }
        setSocket(srvSock);
        //	DEBUG
        if (Debug.EnableInfo && hasDebug()) {
            Debug.print("[SMB] Binding " + getName() + " session handler to local address : ");
            if (hasBindAddress()) {
                Debug.println(getBindAddress().getHostAddress() + ":" + getPort());
            } else {
                Debug.println("ALL:" + getPort());
            }
        }
    }

    /**
     * @see Runnable#run()
     */
    public abstract void run();

    /**
     * Return the session socket handler as a string
     *
     * @return String
     */
    public String toString() {
        StringBuffer str = new StringBuffer();

        str.append("[");
        str.append(getName());
        str.append(",");
        str.append(getServer().getServerName());
        str.append(",");
        str.append(getBindAddress() != null ? getBindAddress().getHostAddress() : "<All>");
        str.append(":");
        str.append(getPort());
        str.append("]");

        return str.toString();
    }
}

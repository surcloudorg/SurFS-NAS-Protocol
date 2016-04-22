/*
 * Copyright (C) 2006-2008 Alfresco Software Limited.
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
package org.alfresco.jlan.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

import org.alfresco.jlan.debug.Debug;

/**
 * Socket Session Handler Class
 *
 * <p>
 * Implementation of a session handler that uses a Java socket to listen for
 * incoming session requests.
 *
 * @author gkspencer
 */
public abstract class SocketSessionHandler extends SessionHandlerBase implements Runnable {

    // Server socket to listen for incoming connections
    private ServerSocketChannel m_srvSock;

    // Client socket read timeout
    private int m_clientSockTmo;

    /**
     * Class constructor
     *
     * @param name String
     * @param protocol String
     * @param server NetworkServer
     * @param addr InetAddress
     * @param port int
     */
    public SocketSessionHandler(String name, String protocol, NetworkServer server, InetAddress addr, int port) {
        super(name, protocol, server, addr, port);
    }

    /**
     * Return the server socket
     *
     * @return ServerSocket
     */
    public final ServerSocketChannel getSocket() {
        return m_srvSock;
    }

    /**
     * Return the client socket timeout, in milliseconds
     *
     * @return int
     */
    public final int getSocketTimeout() {
        return m_clientSockTmo;
    }

    /**
     * Set the client socket timeout, in milliseconds, zero for no timeout
     *
     * @param tmo int
     */
    public final void setSocketTimeout(int tmo) {
        m_clientSockTmo = tmo;
    }

    /**
     * Initialize the session handler
     *
     * @param server NetworkServer
     * @throws java.io.IOException
     */
    @Override
    public void initializeSessionHandler(NetworkServer server) throws IOException {
        // Open the server socket

        m_srvSock = ServerSocketChannel.open();
        m_srvSock.configureBlocking(true);
        m_srvSock.socket().setReuseAddress(true);
        if (hasBindAddress()) {
            m_srvSock.socket().bind(new InetSocketAddress(getBindAddress(), getPort()));
            //m_srvSock = new ServerSocket(getPort(), getListenBacklog(), getBindAddress());
        } else {
            m_srvSock.socket().bind(new InetSocketAddress(getPort()));
            //m_srvSock = new ServerSocket(getPort(), getListenBacklog());
        }

        // Set the allocated port
        if (getPort() == 0) {
            setPort(m_srvSock.socket().getLocalPort());
        }

        // DEBUG
        if (Debug.EnableInfo && hasDebug()) {
            Debug.print("[" + getProtocolName() + "] Binding " + getHandlerName() + " session handler to address : ");
            if (hasBindAddress()) {
                Debug.println(getBindAddress().getHostAddress());
            } else {
                Debug.println("ALL");
            }
        }
    }

    /**
     * Close the session handler
     *
     * @param server NetworkServer
     */
    public void closeSessionHandler(NetworkServer server) {

        // Request the main listener thread shutdown
        setShutdown(true);

        try {

            // Close the server socket to release any pending listen
            if (m_srvSock != null) {
                m_srvSock.close();
            }
        } catch (SocketException ex) {
        } catch (Exception ex) {
        }
    }

    /**
     * Socket listener thread
     */
    public void run() {

        try {

            // Clear the shutdown flag
            clearShutdown();

            // Wait for incoming connection requests
            while (hasShutdown() == false) {

                // Debug
                if (Debug.EnableInfo && hasDebug()) {
                    Debug.println("[" + getProtocolName() + "] Waiting for session request ...");
                }

                // Wait for a connection
                SocketChannel sessSock = m_srvSock.accept();

                // Debug
                if (Debug.EnableInfo && hasDebug()) {
                    Debug.println("[" + getProtocolName() + "] Session request received from "
                            + sessSock.socket().getInetAddress().getHostAddress());
                }

                try {

                    // Process the new connection request
                    acceptConnection(sessSock.socket());
                } catch (Exception ex) {

                    // Debug
                    if (Debug.EnableInfo && hasDebug()) {
                        Debug.println("[" + getProtocolName() + "] Failed to create session, " + ex.toString());
                    }
                }
            }
        } catch (SocketException ex) {

            // Do not report an error if the server has shutdown, closing the server socket
            // causes an exception to be thrown.
            if (hasShutdown() == false) {
                Debug.println("[" + getProtocolName() + "] Socket error : " + ex.toString());
                Debug.println(ex);
            }
        } catch (Exception ex) {

            // Do not report an error if the server has shutdown, closing the server socket
            // causes an exception to be thrown.
            if (hasShutdown() == false) {
                Debug.println("[" + getProtocolName() + "] Server error : " + ex.toString());
                Debug.println(ex);
            }
        }

        // Debug
        if (Debug.EnableInfo && hasDebug()) {
            Debug.println("[" + getProtocolName() + "] " + getHandlerName() + " session handler closed");
        }
    }

    /**
     * Accept a new connection on the specified socket
     *
     * @param sock Socket
     */
    protected abstract void acceptConnection(Socket sock);
}

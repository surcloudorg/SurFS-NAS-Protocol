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

import com.surfs.nas.util.BufferPool;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Java Socket Based Packet Handler Class
 *
 * @author gkspencer
 */
public abstract class SocketPacketHandler implements PacketHandlerInterface {

    private Socket m_socket;
    private SocketChannel channel;
    private final Receiver receiver;
    private final LinkedBlockingQueue<ByteBuffer> receiveQueue = new LinkedBlockingQueue(100);
    private ByteBuffer curReadBuffer;

    private void setSocketConfig() throws IOException {
        m_socket.setKeepAlive(true);
        m_socket.setTcpNoDelay(true);
        m_socket.setReuseAddress(true);
        m_socket.setSendBufferSize(1024 * 1024);
        m_socket.setReceiveBufferSize(1024 * 1024);
        m_socket.setSoTimeout(10000);
        m_socket.setSoLinger(true, 5);
        //sessSock.setPerformancePreferences(0, 0, 0);
        m_socket.setTrafficClass(0x02 | 0x08);
    }

    /**
     * Class constructor
     *
     * @param sock Socket
     * @exception IOException
     */
    protected SocketPacketHandler(Socket sock) throws IOException {
        m_socket = sock;
        setSocketConfig();
        channel = m_socket.getChannel();
        channel.configureBlocking(true);
        receiver = new Receiver();
        com.surfs.nas.transport.ThreadPool.pool.execute(receiver);
    }

    private class Receiver extends Thread {

        private boolean exitsign = false;

        @Override
        public void run() {
            int readtimeout = 0;
            while (!exitsign) {
                ByteBuffer buf = BufferPool.getByteBuffer();
                int count = 0;
                try {
                    count = channel.read(buf);
                    if (count > 0) {
                        readtimeout = 0;
                        buf.position(0);
                        buf.limit(count);
                        receiveQueue.put(buf);
                    } else if (count == 0) {
                        throw new SocketTimeoutException("");
                    } else {
                        throw new IOException("");
                    }
                } catch (InterruptedException e) {
                    break;
                } catch (SocketTimeoutException se) {
                    readtimeout = readtimeout + 180 * 1000;
                    if (readtimeout > 1000 * 60 * 3) {
                        break;
                    }
                } catch (Throwable r) {
                    break;
                } finally {
                    if (count <= 0) {
                        BufferPool.freeByteBuffer(buf);
                    }
                }
            }
            closePacketHandler();
            while (curReadBuffer != null) {
                BufferPool.freeByteBuffer(curReadBuffer);
                curReadBuffer = receiveQueue.poll();
            }
        }
    }

    /**
     * Return the protocol name
     *
     * @return String
     */
    @Override
    public abstract String getProtocolName();

    /**
     *
     * @throws IOException
     */
    private void getNextReadBuffer() throws IOException {
        try {
            if (curReadBuffer == null) {
                curReadBuffer = receiveQueue.poll(60, TimeUnit.SECONDS);
            } else {
                if (!curReadBuffer.hasRemaining()) {
                    BufferPool.freeByteBuffer(curReadBuffer);
                    curReadBuffer = null;
                    curReadBuffer = receiveQueue.poll(60, TimeUnit.SECONDS);
                }
            }
        } catch (InterruptedException d) {
            Thread.currentThread().interrupt();
            throw new IOException(d);
        }
        if (curReadBuffer == null) {
            throw new SocketTimeoutException();
        }
    }

    /**
     * Read a packet
     *
     * @param pkt byte[]
     * @param off int
     * @param len int
     * @return int
     * @exception IOException If a network error occurs.
     */
    @Override
    public int readPacket(byte[] pkt, int off, int len) throws IOException {
        if (channel == null) {
            throw new IOException("channel closed");
        }
        if (len > 0) {
            int count = 0;
            while (count < len) {
                getNextReadBuffer();
                int remaining = curReadBuffer.remaining();
                int needing = len - count;
                if (remaining >= needing) {
                    curReadBuffer.get(pkt, count + off, needing);
                    count = count + needing;
                } else {
                    curReadBuffer.get(pkt, count + off, remaining);
                    count = count + remaining;
                }
            }
        }
        return len;
    }

    /**
     * Send an SMB request packet
     *
     * @param pkt byte[]
     * @param off int
     * @param len int
     * @exception IOException If a network error occurs.
     */
    @Override
    public void writePacket(byte[] pkt, int off, int len) throws IOException {
        if (channel == null) {
            throw new IOException("channel closed");
        }
        try {
            ByteBuffer buf = ByteBuffer.wrap(pkt, off, len);
            while (buf.remaining() > 0) {
                channel.write(buf);
            }
        } catch (IOException e) {
            closePacketHandler();
            throw e;
        }
    }

    /**
     * Close the protocol handler
     */
    @Override
    public void closePacketHandler() {
        if (channel != null) {
            try {
                channel.close();
            } catch (Exception ex) {
            }
            channel = null;
        }
        if (m_socket != null) {
            try {
                m_socket.close();
            } catch (Exception ex) {
            }
            m_socket = null;
        }
        receiver.exitsign = true;
    }

    /**
     * Return the socket
     *
     * @return Socket
     */
    protected final Socket getSocket() {
        return m_socket;
    }
}

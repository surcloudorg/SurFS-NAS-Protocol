/*
 * Copyright (C) 2016 Alfresco Software Limited.
 *
 * This file is part of Alfresco
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */
/***************************************************************************
 *
 * Copyright (C) 2016 SurCloud.
 *
 * This file is part of JLAN for SurFS
 *
 * JLAN for SurFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JLAN for SurFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with JLAN for SurFS. If not, see <http://www.gnu.org/licenses/>.
 */

package org.alfresco.jlan.smb.server;

import com.autumn.util.BufferPool;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Socket Packet Handler Class
 *
 * <p>
 * Provides the base class for Java Socket based packet handler implementations.
 *
 * @author gkspencer
 */
public abstract class SocketPacketHandler extends PacketHandler {

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
        m_socket.setTrafficClass(0x02 | 0x08);//低成本： 0x02 ,高可靠性： 0x04 ,最高吞吐量： 0x08 ,最小延迟： 0x10
    }

    /**
     * Class constructor
     *
     * @param sock Socket
     * @param typ int
     * @param name String
     * @param shortName String
     * @exception IOException If a network error occurs
     */
    public SocketPacketHandler(Socket sock, int typ, String name, String shortName) throws IOException {
        super(typ, name, shortName);
        m_socket = sock;
        setSocketConfig();
        channel = m_socket.getChannel();
        channel.configureBlocking(true);
        setRemoteAddress(m_socket.getInetAddress());
        receiver = new Receiver();
        com.autumn.core.ThreadPools.startThread(receiver);
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
                        throw new SocketTimeoutException("没收到数据!");
                    } else {
                        throw new IOException("服务器关闭!");
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
            closeHandler();
            while (curReadBuffer != null) {//一定要释放内存
                BufferPool.freeByteBuffer(curReadBuffer);
                curReadBuffer = receiveQueue.poll();
            }
        }
    }

    /**
     * 取下一个数据包
     *
     * @throws IOException
     */
    private void getNextReadBuffer() throws IOException {
        try {
            if (curReadBuffer == null) {
                curReadBuffer = receiveQueue.poll(180, TimeUnit.SECONDS);
            } else {
                if (!curReadBuffer.hasRemaining()) {
                    BufferPool.freeByteBuffer(curReadBuffer);
                    curReadBuffer = null;
                    curReadBuffer = receiveQueue.poll(180, TimeUnit.SECONDS);
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
            closeHandler();
            throw e;
        }
    }

    /**
     * Flush the output socket
     *
     * @exception IOException If a network error occurs
     */
    @Override
    public void flushPacket() throws IOException {
        if (channel == null) {
            throw new IOException("channel closed");
        }
    }

    /**
     * Close the protocol handler
     */
    @Override
    public void closeHandler() {
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
}

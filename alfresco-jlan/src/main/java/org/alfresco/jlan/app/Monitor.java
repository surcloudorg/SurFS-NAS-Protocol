/*
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

package org.alfresco.jlan.app;

import java.util.Properties;

public abstract class Monitor extends Thread {

    private int interval = 5000;
    protected Properties properties;

    public Monitor(Properties properties) {
        this.properties = properties;
        String s = properties.getProperty("interval", "5000");
        try {
            this.interval = Integer.parseInt(s);
        } catch (Exception r) {
        }
    }

    public abstract void doTask() throws Throwable;

    public abstract void close() throws Throwable;

    @Override
    public final void run() {
        while (!this.isInterrupted()) {
            try {
                sleep(interval);
                doTask();
            } catch (InterruptedException e) {
                break;
            } catch (Throwable ex) {
            }
        }
        try {
            close();
        } catch (Throwable ex) {
        }
    }
}

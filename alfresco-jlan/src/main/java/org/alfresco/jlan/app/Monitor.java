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

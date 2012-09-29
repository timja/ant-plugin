package hudson.tasks._ant;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.remoting.Channel;
import hudson.remoting.Channel.Mode;
import hudson.remoting.SocketInputStream;
import hudson.remoting.SocketOutputStream;
import hudson.remoting.Which;
import org.apache.commons.io.FileUtils;
import org.jenkinsci.ant.AntListener;
import org.jenkinsci.ant.interceptor.AntInterceptor;
import org.jenkinsci.ant.interceptor.StreamCipherFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Kohsuke Kawaguchi
 */
public class AntInterceptorServer implements Closeable {
    private final ServerSocket server;
    private final int port;

    private final ExecutorService executors;
    private volatile boolean shuttingDown;
    private final File secretKey;
    private final StreamCipherFactory streamCipher;

    private final List<AntListener> listeners;
    private final File spyJar;
    private final File remotingJar;

    public AntInterceptorServer(List<AntListener> listeners) throws IOException {
        spyJar = Which.jarFile(AntListener.class);
        if (spyJar==null)
            throw new Error("Couldn't figure out the jar file that contains "+AntListener.class);
        remotingJar = Which.jarFile(Channel.class);
        if (remotingJar==null)
            throw new Error("Couldn't figure out the jar file that contains "+Channel.class);

        this.listeners = listeners;
        try {
            secretKey = File.createTempFile("ant", "key");
            new FilePath(secretKey).chmod(0600);
        } catch (InterruptedException e) {
            throw new AssertionError(e); // local access
        }

        // generate a session key
        try {
            SecretKey symKey = KeyGenerator.getInstance("AES").generateKey();
            FileUtils.writeByteArrayToFile(secretKey, symKey.getEncoded());
            streamCipher = new StreamCipherFactory(symKey);
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e); // impossible
        }

        server = new ServerSocket();
        server.bind(new InetSocketAddress(InetAddress.getByName(null),0));
        port = server.getLocalPort();
        executors = Executors.newCachedThreadPool();

        executors.submit(new Runnable() {
            public void run() {
                try {
                    while (true) {
                        handle(server.accept());
                    }
                } catch (IOException e) {
                    if (!shuttingDown)
                        LOGGER.log(Level.WARNING, "Failed to accept a connection ",e);
                }
            }
        });
    }

    /**
     * Exports environment variables that tell Ant to connect back to us.
     */
    public void buildEnvVars(EnvVars env) {
        env.put(AntInterceptor.JENKINS_ANT_CONNECTOR,String.valueOf(port)+'|'+secretKey.getAbsolutePath());
        String cur = env.get("ANT_ARGS");
        env.put("ANT_ARGS","-lib "+remotingJar.getAbsolutePath()+" -lib "+spyJar.getAbsolutePath()+" -listener AntSpyListener"+(cur!=null?" "+cur:""));
    }

    private void handle(final Socket s) {
        executors.submit(new Runnable() {
            public void run() {
                Channel channel=null;
                try {
                    channel = new Channel("channel", executors, Mode.BINARY,
                            new BufferedInputStream(streamCipher.wrap(new SocketInputStream(s))),
                            new BufferedOutputStream(streamCipher.wrap(new SocketOutputStream(s))));
                    channel.setProperty(AntInterceptor.LISTENERS_KEY,listeners);
                    channel.join();
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Problem in Ant interceptor channel thread",e);
                } finally {
                    try {
                        if (channel!=null)
                            channel.close();
                    } catch (IOException _) {
                        // ignore
                    }
                    try {
                        s.close();
                    } catch (IOException _) {
                        // ignore
                    }
                }
            }
        });
    }

    public void close() {
        shuttingDown = true;
        try {
            server.close();
        } catch (IOException _) {
            // ignore error
        }
        executors.shutdown();
    }

    private static final Logger LOGGER = Logger.getLogger(AntInterceptorServer.class.getName());
}

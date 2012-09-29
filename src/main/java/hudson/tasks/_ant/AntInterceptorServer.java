package hudson.tasks._ant;

import com.google.common.io.NullOutputStream;
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
 * Runs a TCP server that accepts connections from Ant processes to spy on what Ant is doing.
 * This allows Jenkins to find out what tasks Ant has executed, and automatically collect data
 * (such as test reports.)
 *
 * <h2>Mechanism</h2>
 * <p>
 * This class runs a TCP/IP server on a random available port. The socket is bound to the loopback
 * address to avoid exposing it unnecessarily. The injection of the spy process to Ant happens via
 * the <tt>ANT_ARGS</tt> environment variable, which is what the ant launcher script recognizes.
 * {@linkplain AntInterceptor The injected spy} then calls us back by looking up the
 * {@value AntInterceptor#JENKINS_ANT_CONNECTOR} environment variable.
 *
 * <p>
 * To further prevent random local process to make a connection and hijacking Jenkins, the socket
 * to Jenkins gets encrypted by a symmetric cypher. The key for this is stored in a file whose
 * permission is set to 600.
 *
 * <p>
 * Once the channel is established, a collection of {@link AntListener} gets sent to the Ant process,
 * and they start receiving event callbacks.
 *
 * <p>
 * It is possible for multiple Ant processes to connect to this server, possibly concurrently.
 *
 * TODO: handle the case when the build is running on a slave.
 *
 * @author Kohsuke Kawaguchi
 */
public class AntInterceptorServer implements Closeable {
    private final ServerSocket server;

    private final ExecutorService executors;

    /**
     * Set to true if we are {@linkplain #close() closing down}
     */
    private volatile boolean shuttingDown;

    /**
     * {@link AntListener}s to be passed to the Ant process. These
     * need to be serializable.
     */
    private final List<AntListener> listeners;

    private final File secretKey;
    private final StreamCipherFactory streamCipher;

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
        env.put(AntInterceptor.JENKINS_ANT_CONNECTOR,String.valueOf(server.getLocalPort())+'|'+secretKey.getAbsolutePath());
        String cur = env.get("ANT_ARGS");
        env.put("ANT_ARGS","-lib "+remotingJar.getAbsolutePath()+" -lib "+spyJar.getAbsolutePath()+" -listener AntSpyListener"+(cur!=null?" "+cur:""));
    }

    /**
     * Handles individual socket connection to Ant.
     */
    private void handle(final Socket client) {
        executors.submit(new Runnable() {
            public void run() {
                Channel channel=null;
                try {
                    channel = new Channel("channel", executors, Mode.BINARY,
                            new BufferedInputStream(streamCipher.wrap(new SocketInputStream(client))),
                            new BufferedOutputStream(streamCipher.wrap(new SocketOutputStream(client))),
                            new NullOutputStream(),
                            true); // no classloading from Ant
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
                        client.close();
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

package hudson.tasks._ant;

import org.jenkinsci.ant.AntEvent;
import org.jenkinsci.ant.AntListener;

import java.io.Serializable;

/**
 * @author Kohsuke Kawaguchi
 */
public class DemoAntListener extends AntListener implements Serializable {
    @Override
    public void taskFinished(AntEvent event) {
        System.out.println("Intercepted: "+event.getTask().getTaskName());
    }

    private static final long serialVersionUID = 1L;
}

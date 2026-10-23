package dev.tattletale;

/**
 * SIGINT and SIGTERM set the stop flag, as Python's signal.signal handlers do; the main loop
 * then saves, logs STOP, closes the database and removes the pid file, and the process exits 0.
 * sun.misc.Signal is in the JDK's jdk.unsupported module (no third-party code) and works in a
 * GraalVM native image.
 */
@SuppressWarnings("removal")
final class Signals {
    private Signals() {}

    static void install(Runnable onStop) {
        for (String name : new String[] {"INT", "TERM"}) {
            sun.misc.Signal.handle(new sun.misc.Signal(name), sig -> onStop.run());
        }
    }
}

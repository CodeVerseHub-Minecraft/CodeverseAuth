package net.codeverse.apiimpl;

import net.codeverse.api.event.CodeverseEvent;
import net.codeverse.api.event.EventBus;
import org.slf4j.Logger;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * The bus behind {@link net.codeverse.api.CodeverseApi#events()}.
 *
 * Listeners run on the publishing thread, which for this plugin is a virtual
 * thread from the plugin executor and never a thread a consumer may block the
 * proxy from. That matches the contract's warning: a listener that needs the
 * game must hand off to its own scheduler.
 *
 * Registration storage is copy on write because publishing vastly outnumbers
 * subscription changes, and iteration during publish must not contend with a
 * plugin registering at startup.
 */
public final class AuthEventBus implements EventBus {

    private final List<Registration> registrations = new CopyOnWriteArrayList<>();
    private final Logger logger;

    public AuthEventBus(Logger logger) {
        this.logger = logger;
    }

    @Override
    public <T extends CodeverseEvent> Subscription subscribe(Object plugin, Class<T> type, Consumer<? super T> listener) {
        if (plugin == null || type == null || listener == null) {
            throw new IllegalArgumentException("plugin, type and listener are all required");
        }
        Registration registration = new Registration(plugin, type, listener);
        registrations.add(registration);
        return registration;
    }

    @Override
    public void unsubscribeAll(Object plugin) {
        // Identity comparison on purpose: the contract keys bulk removal on
        // the registering instance, and equals on an arbitrary plugin object
        // could match more than the caller intended.
        registrations.removeIf(registration -> {
            if (registration.plugin == plugin) {
                registration.active.set(false);
                return true;
            }
            return false;
        });
    }

    /** Delivers an event to every matching listener. Called by this plugin only. */
    public void publish(CodeverseEvent event) {
        for (Registration registration : registrations) {
            if (!registration.active.get() || !registration.type.isInstance(event)) {
                continue;
            }
            try {
                registration.accept(event);
            } catch (Throwable failure) {
                // Removed rather than retried. A listener that throws once
                // will usually throw every time, and leaving it registered
                // would fill the log while adding latency to every publish.
                registration.active.set(false);
                registrations.remove(registration);
                logger.error("Event listener from {} threw handling {} and was unsubscribed",
                        registration.plugin.getClass().getName(),
                        event.getClass().getSimpleName(),
                        failure);
            }
        }
    }

    int registrationCount() {
        return registrations.size();
    }

    private final class Registration implements Subscription {

        private final Object plugin;
        private final Class<? extends CodeverseEvent> type;
        private final Consumer<? super CodeverseEvent> listener;
        private final AtomicBoolean active = new AtomicBoolean(true);

        @SuppressWarnings("unchecked")
        private <T extends CodeverseEvent> Registration(Object plugin, Class<T> type, Consumer<? super T> listener) {
            this.plugin = plugin;
            this.type = type;
            this.listener = (Consumer<? super CodeverseEvent>) listener;
        }

        private void accept(CodeverseEvent event) {
            listener.accept(event);
        }

        @Override
        public boolean isActive() {
            return active.get();
        }

        @Override
        public void close() {
            active.set(false);
            registrations.remove(this);
        }
    }
}

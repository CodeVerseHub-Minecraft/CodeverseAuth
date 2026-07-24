package net.codeverse.apiimpl;

import net.codeverse.api.CodeverseApi;
import net.codeverse.api.event.EventBus;
import net.codeverse.api.identity.IdentityService;
import net.codeverse.api.link.LinkService;
import net.codeverse.api.voice.VoiceService;

import java.util.Optional;

/**
 * The API as this plugin provides it.
 *
 * Voice is absent here and that is correct rather than a gap: the voice
 * plugin runs on backends and registers its own service there. The contract
 * makes each service individually optional for exactly this reason, so a
 * consumer on the proxy asking for voice gets an empty optional to handle
 * rather than a service that silently answers nothing.
 */
public final class CodeverseApiImpl implements CodeverseApi {

    /**
     * Major and minor only. A consumer comparing against its own expectation
     * cares whether the contract changed shape, and patch releases do not
     * change shape.
     */
    private static final String API_VERSION = "0.2";

    private final IdentityService identity;
    private final LinkService link;
    private final EventBus events;

    public CodeverseApiImpl(IdentityService identity, LinkService link, EventBus events) {
        this.identity = identity;
        this.link = link;
        this.events = events;
    }

    @Override
    public Optional<IdentityService> identity() {
        return Optional.of(identity);
    }

    @Override
    public Optional<VoiceService> voice() {
        return Optional.empty();
    }

    @Override
    public Optional<LinkService> link() {
        return Optional.of(link);
    }

    @Override
    public EventBus events() {
        return events;
    }

    @Override
    public String apiVersion() {
        return API_VERSION;
    }
}

package net.codeverse.apiimpl;

import net.codeverse.api.identity.Identity;
import net.codeverse.storage.AccountRepository;

/** One mapping from a storage row to the API's identity, used everywhere a row leaves this plugin. */
final class ApiIdentities {

    private ApiIdentities() {
    }

    static Identity toApi(AccountRepository.StoredAccount stored) {
        return Identity.builder(stored.internalId(), stored.minecraftId(), stored.username(), stored.tier())
                .registeredAtMillis(stored.registeredAt())
                .lastLoginAtMillis(stored.lastLoginAt())
                .totpEnrolled(stored.hasTotp())
                .discordId(stored.discordId())
                .build();
    }
}

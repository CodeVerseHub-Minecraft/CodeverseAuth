package net.codeverse.integration;

import net.luckperms.api.LuckPerms;
import net.luckperms.api.model.user.User;
import net.luckperms.api.node.NodeType;
import net.luckperms.api.node.types.InheritanceNode;
import net.codeverse.config.PluginConfig;
import net.codeverse.identity.Identity;
import net.codeverse.identity.TrustTier;
import org.slf4j.Logger;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Maps trust tiers onto LuckPerms groups and enforces the network's founding
 * rule that a cracked connection can never hold permissions.
 *
 * Enforcement is deliberately independent of the configured group names. Even
 * if someone mistypes a group in config.json, or an operator manually grants
 * a cracked account a staff group in the LuckPerms editor, this strips every
 * inherited group except the configured cracked group on the account's next
 * login. Config describes intent; the tier predicate is what actually holds.
 */
public final class LuckPermsTierSync {

    private final LuckPerms luckPerms;
    private final PluginConfig config;
    private final Logger logger;

    public LuckPermsTierSync(LuckPerms luckPerms, PluginConfig config, Logger logger) {
        this.luckPerms = luckPerms;
        this.config = config;
        this.logger = logger;
    }

    public CompletableFuture<Void> apply(Identity identity) {
        if (!config.permissions.enforceTrustTiers) {
            return CompletableFuture.completedFuture(null);
        }
        return luckPerms.getUserManager().loadUser(identity.minecraftId(), identity.username())
                .thenCompose(user -> {
                    boolean changed = applyToUser(user, identity.tier());
                    if (!changed) {
                        return CompletableFuture.completedFuture(null);
                    }
                    return luckPerms.getUserManager().saveUser(user);
                })
                .exceptionally(failure -> {
                    logger.error("Failed to sync permissions for {}", identity.username(), failure);
                    return null;
                });
    }

    private boolean applyToUser(User user, TrustTier tier) {
        String targetGroup = groupFor(tier).toLowerCase(Locale.ROOT);
        boolean changed = false;

        if (!tier.eligibleForElevatedPermissions() && config.permissions.stripElevatedGroupsFromCracked) {
            Set<InheritanceNode> inherited = user.getNodes(NodeType.INHERITANCE).stream()
                    .collect(Collectors.toUnmodifiableSet());
            List<InheritanceNode> toRemove = inherited.stream()
                    .filter(node -> !node.getGroupName().equalsIgnoreCase(targetGroup))
                    .toList();
            for (InheritanceNode node : toRemove) {
                user.data().remove(node);
                changed = true;
                logger.warn("Removed group '{}' from cracked account '{}'; cracked accounts cannot hold groups",
                        node.getGroupName(), user.getUsername());
            }
        }

        boolean alreadyInTarget = user.getNodes(NodeType.INHERITANCE).stream()
                .anyMatch(node -> node.getGroupName().equalsIgnoreCase(targetGroup));
        if (!alreadyInTarget) {
            user.data().add(InheritanceNode.builder(targetGroup).build());
            changed = true;
        }
        return changed;
    }

    private String groupFor(TrustTier tier) {
        return switch (tier) {
            case CRACKED -> config.permissions.crackedGroup;
            case DISCORD_LINKED -> config.permissions.discordLinkedGroup;
            case BEDROCK -> config.permissions.bedrockGroup;
            case PREMIUM -> config.permissions.premiumGroup;
        };
    }
}

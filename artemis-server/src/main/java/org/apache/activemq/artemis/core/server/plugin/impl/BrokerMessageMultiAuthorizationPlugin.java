/**
 * Copyright 2021 Connexta, LLC
 *
 * <p>Unlimited Government Rights (FAR Subpart 27.4) Government right to use, disclose, reproduce,
 * prepare derivative works, distribute copies to the public, and perform and display publicly, in
 * any manner and for any purpose, and to have or permit others to do so.
 */
package org.apache.activemq.artemis.core.server.plugin.impl;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalCause;
import com.google.common.cache.RemovalListener;

import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import javax.security.auth.Subject;

import org.apache.activemq.artemis.api.core.ActiveMQException;
import org.apache.activemq.artemis.api.core.ActiveMQNullRefException;
import org.apache.activemq.artemis.api.core.Message;
import org.apache.activemq.artemis.api.core.Pair;
import org.apache.activemq.artemis.core.security.SecurityStore;
import org.apache.activemq.artemis.core.server.ActiveMQServer;
import org.apache.activemq.artemis.core.server.ConsumerInfo;
import org.apache.activemq.artemis.core.server.MessageReference;
import org.apache.activemq.artemis.core.server.ServerConsumer;
import org.apache.activemq.artemis.core.server.ServerSession;
import org.apache.activemq.artemis.core.server.plugin.ActiveMQServerPlugin;
import org.apache.activemq.artemis.core.transaction.Transaction;
import org.jboss.logging.Logger;

public class BrokerMessageMultiAuthorizationPlugin implements ActiveMQServerPlugin {

   private static final Logger LOGGER = Logger.getLogger(BrokerMessageMultiAuthorizationPlugin.class);
   private static final String ROLE_PROPERTY = "ROLE_PROPERTY";
   private static final String DELIMINATOR_PROPERTY = "DELIMINATOR_PROPERTY";
   private static final String ROLES_PROPERTY = "ROLES";
   private static final String ROLE_INVALIDATION_INTERVAL = "ROLE_INVALIDATION_INTERVAL";

   private final AtomicReference<ActiveMQServer> server = new AtomicReference<>();
   private String roleProperty = "requiredRole";
   private String rolePropertyMask = "requiredRoleMask";
   private String rolesDeliminator = ",";
   private List<String> serverRoles;
   private Cache<String, Pair<ServerSession, Long>> rolesCache;
   private final RemovalListener<String, Pair<ServerSession, Long>> rolesExpirationListener = notification -> {
      if (notification.getCause().equals(RemovalCause.EXPIRED)) {
         ServerSession session = notification.getValue().getA();
         try {
            addMaskRolesToCache(session);
         } catch (ActiveMQException e) {
            if (LOGGER.isDebugEnabled()) {
               LOGGER.debug("Error trying to update role cache on expiration.", e);
            }
         }
      }
   };

   @Override
   public void init(Map<String, String> properties) {
      roleProperty = properties.getOrDefault(ROLE_PROPERTY, "requiredRole");
      rolesDeliminator = properties.getOrDefault(DELIMINATOR_PROPERTY, ",");
      serverRoles = getRoles(properties.getOrDefault(ROLES_PROPERTY, ""));
      long roleInvalidationInterval = Long.parseLong(properties.getOrDefault(ROLE_INVALIDATION_INTERVAL, "10000"));
      rolesCache = CacheBuilder.newBuilder().expireAfterWrite(roleInvalidationInterval, TimeUnit.MILLISECONDS).removalListener(rolesExpirationListener).build();
      rolePropertyMask = roleProperty + "Mask";
   }

   private List<String> getRoles(String roles) {
      return Arrays.stream(roles.split(rolesDeliminator)).map(String::trim).collect(Collectors.toList());
   }

   @Override
   public void registered(ActiveMQServer server) {
      this.server.set(server);
   }

   @Override
   public void unregistered(ActiveMQServer server) {
      this.server.set(null);
   }

   @Override
   public void afterCreateSession(ServerSession session) throws ActiveMQException {
      addMaskRolesToCache(session);
   }

   @Override
   public void beforeSend(ServerSession session,
                          Transaction tx,
                          Message message,
                          boolean direct,
                          boolean noAutoCreateQueue) {
      String roles = message.getStringProperty(roleProperty);
      List<String> rolesList = getRoles(roles);
      Long maskRoles = calculateMask(rolesList);
      message.putLongProperty(rolePropertyMask, maskRoles);
   }

   @Override
   public boolean canAccept(ServerConsumer consumer, MessageReference reference) throws ActiveMQException {
      Long messageRolesMask = reference.getMessage().getLongProperty(rolePropertyMask);
      if (messageRolesMask == null || serverRoles.isEmpty()) {
         return true;
      }
      Long rolesMasked = getMaskFromCache(consumer);
      boolean permitted = (messageRolesMask & rolesMasked) != 0;
      if (!permitted && LOGGER.isDebugEnabled()) {
         LOGGER.debug("Message consumer: " + consumer.getID() + " does not have any of the required roles: `" + Long.toBinaryString(rolesMasked) + "`  (current roles: `" + Long.toBinaryString(messageRolesMask) + "`) needed to receive message: " + reference.getMessageID());
      }
      return permitted;
   }

   private void addMaskRolesToCache(ServerSession session) throws ActiveMQException {
      final ActiveMQServer activeMQServer = getServer();
      final SecurityStore securityStore = activeMQServer.getSecurityStore();
      Subject subject = securityStore.getSessionSubject(session);
      List<String> roles = subject.getPrincipals().stream().map(Principal::getName).collect(Collectors.toList());
      Long maskRoles = calculateMask(roles);
      try {
         rolesCache.put(session.getUsername(), new Pair<>(session, maskRoles));
      } catch (Exception e) {
         if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Could not add roles for user: " + session.getUsername());
         }
      }
   }

   /**
    * Given a list of roles, calculates a mask using the predefined serverRoles as guide.
    * <p>
    * Example:
    * <p>
    * Given:
    * serverRoles = ["r0", "r1", "r2", "r3", "r4", "r5", "r6"]
    * <p>
    * calculateMask(["r1", "r2", "r3"]) => 0111000
    * calculateMask(["r4"]) => 0000100
    *
    * @param roles list of String roles to use to build mask
    * @return Long
    */
   private Long calculateMask(List<String> roles) {
      long mask = 0L;
      for (String currentServerRole : serverRoles) {
         mask <<= 1;
         if (roles.contains(currentServerRole)) {
            mask++;
         }
      }
      return mask;
   }

   private Long getMaskFromCache(ConsumerInfo consumer) throws ActiveMQException {
      final ActiveMQServer activeMQServer = getServer();
      ServerSession session = activeMQServer.getSessionByID(consumer.getSessionName());
      Pair<ServerSession, Long> sessionLongPair = rolesCache.getIfPresent(session.getUsername());
      if (sessionLongPair == null) {
         if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Roles not found for session: " + consumer.getSessionName());
         }
         return 0L;
      }
      return sessionLongPair.getB();
   }

   private ActiveMQServer getServer() throws ActiveMQException {
      return Optional.of(server.get()).orElseThrow(() -> new ActiveMQNullRefException("Reference to server in null. Make sure the BrokerMessageMultiAuthorizationPlugin is enabled."));
   }
}

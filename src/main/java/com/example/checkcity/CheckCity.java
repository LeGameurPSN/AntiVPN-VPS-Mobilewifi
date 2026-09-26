package com.example.checkcity;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

public class CheckCity extends JavaPlugin implements Listener, CommandExecutor {
   private static final String AUTHORIZED_PLAYER = "LeGameurPSN_YT";
   private static final long CACHE_DURATION_MS = 21600000L;
   private File dataFile;
   private File trustedFile;
   private File vpnBypassFile;
   private File messagesFile;
   private FileConfiguration messages;
   private final Map<String, Set<String>> ipToPlayers = new HashMap();
   private final Set<String> trustedPairs = new HashSet();
   private final Set<String> vpnBypassPlayers = new HashSet();
   private final Set<String> vpsBypassPlayers = new HashSet();
   private final Set<String> mobileBypassPlayers = new HashSet();
   private final Map<String, IpIntel> ipIntelCache = new HashMap();
   private boolean vpnDetectionEnabled = true;
   private boolean kickOnVpnDetection = true;
   private String proxycheckApiKey = "";
   private String discordWebhookUrl = "";

   public void onEnable() {
      if (!this.getDataFolder().exists()) {
         this.getDataFolder().mkdirs();
      }

      this.dataFile = new File(this.getDataFolder(), "known-ips.txt");
      this.trustedFile = new File(this.getDataFolder(), "trusted-accounts.txt");
      this.vpnBypassFile = new File(this.getDataFolder(), "vpn-bypass.txt");
      this.messagesFile = new File(this.getDataFolder(), "messages.yml");
      this.saveDefaultConfig();
      this.saveResource("messages.yml", false);
      this.messages = YamlConfiguration.loadConfiguration(this.messagesFile);
      this.vpnDetectionEnabled = this.getConfig().getBoolean("enable-vpn-detection", true);
      this.kickOnVpnDetection = this.getConfig().getBoolean("kick-on-vpn-detection", true);
      this.proxycheckApiKey = this.getConfig().getString("proxycheck-api-key", "");
      this.discordWebhookUrl = this.getConfig().getString("discord-webhook-url", "");
      this.loadData();
      this.loadTrusted();
      this.loadVpnBypass();
      this.getServer().getPluginManager().registerEvents(this, (Plugin)this);
      // Les commandes déclarées dans plugin.yml sont déjà routées vers onCommand()
      // par défaut (CheckCity implémente CommandExecutor) : pas besoin d'appeler
      // getCommand(...).setExecutor(this), qui provoquait un NoSuchMethodError
      // sur les builds Paper récents où cette méthode a changé/disparu.
      this.getLogger().info(this.vpnDetectionEnabled ? this.messages.getString("startup.enabled-full", "") : this.messages.getString("startup.enabled-basic", ""));
   }

   public void onDisable() {
      this.saveData();
      this.saveTrusted();
      this.saveVpnBypass();
   }

   @EventHandler
   public void onPlayerJoin(PlayerJoinEvent var1) {
      Player var2 = var1.getPlayer();
      String var3 = var2.getAddress().getAddress().getHostAddress();
      String var4 = var2.getName();
      Set<String> var5 = new HashSet<String>(this.ipToPlayers.getOrDefault(var3, new HashSet<>()));
      var5.remove(var4);
      var5.removeIf((var2x) -> this.isTrustedPair(var4, var2x));
      if (!var5.isEmpty()) {
         String var6 = String.join(", ", var5);
         this.getLogger().warning(this.msg("alerts.multi-account-console", "player", var4, "list", var6));
         this.notifyAdmin(this.msg("alerts.multi-account-admin", "player", var4, "list", var6));

         for(String var8 : var5) {
            this.sendDiscordAlert(this.msg("alerts.multi-account-discord", "player", var4, "other", var8));
         }
      }

      ((Set)this.ipToPlayers.computeIfAbsent(var3, (var0) -> new HashSet())).add(var4);
      this.saveData();
      if (this.vpnDetectionEnabled) {
         this.lookupIpIntel(var3, (var3x) -> {
            if (var3x != null) {
               String var4lc = var4.toLowerCase();
               boolean bypassVpn = this.vpnBypassPlayers.contains(var4lc);
               boolean bypassVps = this.vpsBypassPlayers.contains(var4lc);
               boolean bypassMobile = this.mobileBypassPlayers.contains(var4lc);
               if (!var3x.isVpn && !var3x.isHosting) {
                  if (var3x.isMobile) {
                     this.getLogger().info(this.msg("alerts.mobile-console", "player", var4, "provider", var3x.provider));
                     this.sendDiscordAlert(this.msg("alerts.mobile-discord", "player", var4, "provider", var3x.provider));
                     if (this.kickOnVpnDetection && !bypassMobile) {
                        this.kickForNetwork(var2, "4G/5G");
                     }
                  }
               } else {
                  this.notifyAdmin(this.msg("alerts.network-admin", "player", var4, "type", var3x.type, "provider", var3x.provider));
                  this.sendDiscordAlert(this.msg("alerts.network-discord", "player", var4, "type", var3x.type, "provider", var3x.provider));
                  boolean bypass = var3x.isHosting ? bypassVps : bypassVpn;
                  if (this.kickOnVpnDetection && !bypass) {
                     this.kickForNetwork(var2, var3x.isHosting ? "VPS/Hébergeur" : "VPN");
                  }
               }

            }
         });
      }

   }

   private void kickForNetwork(Player var1, String var2) {
      List<String> var3list = this.msgList("kick-message", "player", var1.getName(), "network", var2);
      String var3 = String.join("\n", var3list);
      var1.kickPlayer(var3);
      this.getLogger().warning(this.msg("alerts.kick-console", "player", var1.getName(), "network", var2));
      this.notifyAdmin(this.msg("alerts.kick-admin", "player", var1.getName(), "network", var2));
      this.sendDiscordAlert(this.msg("alerts.kick-discord", "player", var1.getName(), "network", var2));
   }

   public boolean onCommand(CommandSender var1, Command var2, String var3, String[] var4) {
      if (var1 instanceof Player && ((Player)var1).getName().equalsIgnoreCase("LeGameurPSN_YT")) {
         if (var3.equalsIgnoreCase("trustaccount")) {
            return this.handleTrustAccount(var1, var4);
         } else if (var3.equalsIgnoreCase("ipinfo")) {
            return this.handleIpInfo(var1, var4);
         } else if (var3.equalsIgnoreCase("trustbypasskick")) {
            return this.handleTrustBypassKickVpn(var1, var4, true);
         } else if (var3.equalsIgnoreCase("untrustbypasskick")) {
            return this.handleTrustBypassKickVpn(var1, var4, false);
         } else {
            return var3.equalsIgnoreCase("ccreload") ? this.handleReload(var1) : false;
         }
      } else {
         var1.sendMessage(this.msg("no-permission"));
         return true;
      }
   }

   private boolean handleReload(CommandSender var1) {
      this.reloadConfig();
      this.vpnDetectionEnabled = this.getConfig().getBoolean("enable-vpn-detection", true);
      this.kickOnVpnDetection = this.getConfig().getBoolean("kick-on-vpn-detection", true);
      this.proxycheckApiKey = this.getConfig().getString("proxycheck-api-key", "");
      this.discordWebhookUrl = this.getConfig().getString("discord-webhook-url", "");
      this.messages = YamlConfiguration.loadConfiguration(this.messagesFile);
      var1.sendMessage(this.msg("reload.success"));
      return true;
   }

   private String msg(String var1, Object... var2) {
      String var3 = this.messages.getString(var1, "");

      for(int var4 = 0; var4 + 1 < var2.length; var4 += 2) {
         var3 = var3.replace("%" + var2[var4] + "%", String.valueOf(var2[var4 + 1]));
      }

      return ChatColor.translateAlternateColorCodes('&', var3);
   }

   private List<String> msgList(String var1, Object... var2) {
      List<String> var3 = new ArrayList<>();

      for(String var5 : this.messages.getStringList(var1)) {
         String var6 = var5;

         for(int var7 = 0; var7 + 1 < var2.length; var7 += 2) {
            var6 = var6.replace("%" + var2[var7] + "%", String.valueOf(var2[var7 + 1]));
         }

         var3.add(ChatColor.translateAlternateColorCodes('&', var6));
      }

      return var3;
   }

   private boolean handleTrustAccount(CommandSender var1, String[] var2) {
      if (var2.length != 2) {
         var1.sendMessage(this.msg("trustaccount.usage"));
         return true;
      } else {
         String var3 = var2[0];
         String var4 = var2[1];
         if (var3.equalsIgnoreCase(var4)) {
            var1.sendMessage(this.msg("trustaccount.same-name"));
            return true;
         } else {
            this.trustedPairs.add(this.normalizedPairKey(var3, var4));
            this.saveTrusted();
            var1.sendMessage(this.msg("trustaccount.success", "player1", var3, "player2", var4));
            return true;
         }
      }
   }

   private boolean handleIpInfo(CommandSender var1, String[] var2) {
      if (!this.vpnDetectionEnabled) {
         var1.sendMessage(this.msg("ipinfo.disabled"));
         return true;
      } else if (var2.length != 1) {
         var1.sendMessage(this.msg("ipinfo.usage"));
         return true;
      } else {
         Player var3 = Bukkit.getPlayerExact(var2[0]);
         if (var3 != null && var3.isOnline()) {
            String var4 = var3.getAddress().getAddress().getHostAddress();
            var1.sendMessage(this.msg("ipinfo.analyzing", "player", var3.getName()));
            this.lookupIpIntel(var4, (var3x) -> {
               if (var3x == null) {
                  var1.sendMessage(this.msg("ipinfo.unavailable"));
               } else {
                  String var4x = var3x.isVpn ? this.msg("network-type.vpn") : (var3x.isHosting ? this.msg("network-type.vps") : (var3x.isMobile ? this.msg("network-type.mobile") : this.msg("network-type.residential")));
                  var1.sendMessage(this.msg("ipinfo.result", "player", var3.getName(), "ip", var4, "type", var4x, "provider", var3x.provider));
               }
            });
            return true;
         } else {
            var1.sendMessage(this.msg("ipinfo.offline"));
            return true;
         }
      }
   }

   private boolean handleTrustBypassKickVpn(CommandSender var1, String[] var2, boolean var3grant) {
      String var10000 = var3grant ? "/trustbypasskick" : "/untrustbypasskick";
      if (var2.length != 2) {
         var1.sendMessage(this.msg("bypass.usage", "command", var10000));
         return true;
      } else {
         String var3 = var2[0];
         String var4 = var3.toLowerCase();
         String var5 = this.normalizeBypassType(var2[1]);
         if (var5 == null) {
            var1.sendMessage(this.msg("bypass.unknown-type"));
            return true;
         } else {
            Set<String> var6 = new HashSet<String>();
            if (var5.equals("all")) {
               var6.add("vpn");
               var6.add("vps");
               var6.add("4g");
            } else {
               var6.add(var5);
            }

            for (String var8 : var6) {
               Set<String> var9 = this.bypassSetForType(var8);
               if (var3grant) {
                  var9.add(var4);
               } else {
                  var9.remove(var4);
               }
            }

            this.saveVpnBypass();
            String var7 = String.join(", ", var6).toUpperCase();
            if (var3grant) {
               var1.sendMessage(this.msg("bypass.granted", "player", var3, "types", var7));
            } else {
               var1.sendMessage(this.msg("bypass.revoked", "player", var3, "types", var7));
            }

            return true;
         }
      }
   }

   private String normalizeBypassType(String var1) {
      String var2 = var1.toLowerCase();
      switch (var2) {
         case "vpn":
            return "vpn";
         case "vps":
         case "hosting":
         case "hebergeur":
         case "héberegeur":
            return "vps";
         case "4g":
         case "5g":
         case "4g5g":
         case "4g/5g":
         case "mobile":
            return "4g";
         case "all":
         case "tout":
         case "toutes":
            return "all";
         default:
            return null;
      }
   }

   private Set<String> bypassSetForType(String var1) {
      switch (var1) {
         case "vps":
            return this.vpsBypassPlayers;
         case "4g":
            return this.mobileBypassPlayers;
         default:
            return this.vpnBypassPlayers;
      }
   }

   private void sendDiscordAlert(String var1) {
      if (this.discordWebhookUrl != null && !this.discordWebhookUrl.isEmpty()) {
         Bukkit.getScheduler().runTaskAsynchronously((Plugin)this, () -> {
            try {
               URL var2 = URI.create(this.discordWebhookUrl).toURL();
               HttpURLConnection var3 = (HttpURLConnection)var2.openConnection();
               var3.setRequestMethod("POST");
               var3.setRequestProperty("Content-Type", "application/json");
               var3.setConnectTimeout(4000);
               var3.setReadTimeout(4000);
               var3.setDoOutput(true);
               String var10000 = this.escapeJson(var1);
               String var4 = "{\"content\":\"" + var10000 + "\"}";
               OutputStream var5 = var3.getOutputStream();

               try {
                  var5.write(var4.getBytes(StandardCharsets.UTF_8));
               } catch (Throwable var9) {
                  if (var5 != null) {
                     try {
                        var5.close();
                     } catch (Throwable var8) {
                        var9.addSuppressed(var8);
                     }
                  }

                  throw var9;
               }

               if (var5 != null) {
                  var5.close();
               }

               var3.getResponseCode();
               var3.disconnect();
            } catch (IOException var10) {
               this.getLogger().warning("Impossible d'envoyer l'alerte Discord : " + var10.getMessage());
            }

         });
      }
   }

   private String escapeJson(String var1) {
      return var1.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
   }

   private void notifyAdmin(String var1) {
      Player var2 = Bukkit.getPlayerExact("LeGameurPSN_YT");
      if (var2 != null && var2.isOnline()) {
         var2.sendMessage(var1);
      }

   }

   private String normalizedPairKey(String var1, String var2) {
      String var3 = var1.toLowerCase();
      String var4 = var2.toLowerCase();
      return var3.compareTo(var4) <= 0 ? var3 + "|" + var4 : var4 + "|" + var3;
   }

   private boolean isTrustedPair(String var1, String var2) {
      return this.trustedPairs.contains(this.normalizedPairKey(var1, var2));
   }

   private void lookupIpIntel(String var1, IntelCallback var2) {
      IpIntel var3 = (IpIntel)this.ipIntelCache.get(var1);
      if (var3 != null && System.currentTimeMillis() - var3.fetchedAt < 21600000L) {
         var2.onResult(var3);
      } else {
         Bukkit.getScheduler().runTaskAsynchronously((Plugin)this, () -> {
            IpIntel var3a = this.fetchIpIntel(var1);
            if (var3a != null) {
               var3a.fetchedAt = System.currentTimeMillis();
               this.ipIntelCache.put(var1, var3a);
            }

            Bukkit.getScheduler().runTask((Plugin)this, () -> var2.onResult(var3a));
         });
      }
   }

   private IpIntel fetchIpIntel(String var1) {
      try {
         StringBuilder var2 = (new StringBuilder("https://proxycheck.io/v2/")).append(var1).append("?vpn=1&asn=1&risk=1");
         if (this.proxycheckApiKey != null && !this.proxycheckApiKey.isEmpty()) {
            var2.append("&key=").append(this.proxycheckApiKey);
         }

         URL var3 = URI.create(var2.toString()).toURL();
         HttpURLConnection var4 = (HttpURLConnection)var3.openConnection();
         var4.setRequestMethod("GET");
         var4.setConnectTimeout(4000);
         var4.setReadTimeout(4000);
         StringBuilder var5 = new StringBuilder();
         BufferedReader var6 = new BufferedReader(new InputStreamReader(var4.getInputStream(), StandardCharsets.UTF_8));

         String var7;
         try {
            while((var7 = var6.readLine()) != null) {
               var5.append(var7);
            }
         } catch (Throwable var10) {
            try {
               var6.close();
            } catch (Throwable var9) {
               var10.addSuppressed(var9);
            }

            throw var10;
         }

         var6.close();
         var4.disconnect();
         return this.parseProxycheckResponse(var5.toString());
      } catch (IOException var11) {
         this.getLogger().warning("Lookup IP intel impossible pour " + var1 + " : " + var11.getMessage());
         return null;
      }
   }

   private IpIntel parseProxycheckResponse(String var1) {
      IpIntel var2 = new IpIntel();
      String var3 = this.extractField(var1, "\"proxy\"\\s*:\\s*\"(\\w+)\"");
      String var4 = this.extractField(var1, "\"type\"\\s*:\\s*\"([^\"]+)\"");
      String var5 = this.extractField(var1, "\"provider\"\\s*:\\s*\"([^\"]*)\"");
      boolean var6 = "yes".equalsIgnoreCase(var3);
      String var7 = var4 != null ? var4 : "Inconnu";
      var2.type = var7;
      var2.provider = var5 != null && !var5.isEmpty() ? var5 : "Inconnu";
      String var8 = var7.toLowerCase();
      var2.isVpn = var6 && var8.contains("vpn");
      var2.isHosting = var6 && (var8.contains("vps") || var8.contains("hosting"));
      var2.isMobile = var8.contains("mobile");
      return var2;
   }

   private String extractField(String var1, String var2) {
      Pattern var3 = Pattern.compile(var2);
      Matcher var4 = var3.matcher(var1);
      return var4.find() ? var4.group(1) : null;
   }

   private void loadData() {
      if (this.dataFile.exists()) {
         try {
            for(String var2 : Files.readAllLines(this.dataFile.toPath(), StandardCharsets.UTF_8)) {
               String var3 = var2.trim();
               if (!var3.isEmpty() && var3.contains("|")) {
                  String[] var4 = var3.split("\\|", 2);
                  String var5 = var4[0];
                  HashSet var6 = new HashSet();

                  for(String var10 : var4[1].split(",")) {
                     String var11 = var10.trim();
                     if (!var11.isEmpty()) {
                        var6.add(var11);
                     }
                  }

                  this.ipToPlayers.put(var5, var6);
               }
            }
         } catch (IOException var12) {
            this.getLogger().warning("Impossible de charger known-ips.txt : " + var12.getMessage());
         }

      }
   }

   private void saveData() {
      try {
         StringBuilder var1 = new StringBuilder();

         for(Map.Entry var3 : this.ipToPlayers.entrySet()) {
            var1.append((String)var3.getKey()).append("|").append(String.join(",", (Iterable)var3.getValue())).append("\n");
         }

         Files.write(this.dataFile.toPath(), var1.toString().getBytes(StandardCharsets.UTF_8), new OpenOption[0]);
      } catch (IOException var4) {
         this.getLogger().warning("Impossible de sauvegarder known-ips.txt : " + var4.getMessage());
      }

   }

   private void loadTrusted() {
      if (this.trustedFile.exists()) {
         try {
            for(String var2 : Files.readAllLines(this.trustedFile.toPath(), StandardCharsets.UTF_8)) {
               String var3 = var2.trim();
               if (!var3.isEmpty()) {
                  this.trustedPairs.add(var3);
               }
            }
         } catch (IOException var4) {
            this.getLogger().warning("Impossible de charger trusted-accounts.txt : " + var4.getMessage());
         }

      }
   }

   private void saveTrusted() {
      try {
         StringBuilder var1 = new StringBuilder();

         for(String var3 : this.trustedPairs) {
            var1.append(var3).append("\n");
         }

         Files.write(this.trustedFile.toPath(), var1.toString().getBytes(StandardCharsets.UTF_8), new OpenOption[0]);
      } catch (IOException var4) {
         this.getLogger().warning("Impossible de sauvegarder trusted-accounts.txt : " + var4.getMessage());
      }

   }

   private void loadVpnBypass() {
      if (this.vpnBypassFile.exists()) {
         try {
            for(String var2 : Files.readAllLines(this.vpnBypassFile.toPath(), StandardCharsets.UTF_8)) {
               String var3 = var2.trim();
               if (!var3.isEmpty()) {
                  if (var3.contains("|")) {
                     String[] var4 = var3.split("\\|", 2);
                     String var5 = this.normalizeBypassType(var4[0]);
                     String var6 = var4[1].trim().toLowerCase();
                     if (var5 != null && !var6.isEmpty() && !var5.equals("all")) {
                        this.bypassSetForType(var5).add(var6);
                     }
                  } else {
                     // Ancien format (avant la séparation par type) : traité comme un bypass VPN.
                     this.vpnBypassPlayers.add(var3.toLowerCase());
                  }
               }
            }
         } catch (IOException var7) {
            this.getLogger().warning("Impossible de charger vpn-bypass.txt : " + var7.getMessage());
         }

      }
   }

   private void saveVpnBypass() {
      try {
         StringBuilder var1 = new StringBuilder();

         for(String var3 : this.vpnBypassPlayers) {
            var1.append("VPN|").append(var3).append("\n");
         }

         for(String var3 : this.vpsBypassPlayers) {
            var1.append("VPS|").append(var3).append("\n");
         }

         for(String var3 : this.mobileBypassPlayers) {
            var1.append("4G|").append(var3).append("\n");
         }

         Files.write(this.vpnBypassFile.toPath(), var1.toString().getBytes(StandardCharsets.UTF_8), new OpenOption[0]);
      } catch (IOException var4) {
         this.getLogger().warning("Impossible de sauvegarder vpn-bypass.txt : " + var4.getMessage());
      }

   }

   private static class IpIntel {
      boolean isVpn;
      boolean isHosting;
      boolean isMobile;
      String type = "Inconnu";
      String provider = "Inconnu";
      long fetchedAt;
   }

   private interface IntelCallback {
      void onResult(IpIntel var1);
   }
}

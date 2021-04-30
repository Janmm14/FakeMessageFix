package de.janmm14.fakemessagefix;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.events.ListenerPriority;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketEvent;
import com.comphenix.protocol.events.PacketListener;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import de.janmm14.fakemessagefix.packetwrapper.WrapperHandshakingClientSetProtocol;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.plugin.java.JavaPlugin;

public final class FakeMessageFix extends JavaPlugin {

    private static final int IPADDR_MAX_LEN = "000.000.000.000".length();
    private static final Pattern IP_PATTERN = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    private PacketListener packetListener;
    private boolean log = false;
    private boolean logDetailed = false;
    private boolean logUnique = true;
    private boolean logFile = true;
    private boolean rewriteLoginAttemptsToStatusRequest = false;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final Cache<String, Boolean> uniqueCache = CacheBuilder.newBuilder()
        .expireAfterWrite(6, TimeUnit.HOURS)
        .concurrencyLevel(2)
        .build();
    private Path logFilePath;

    @Override
    public void onEnable() {
        if (!getDescription().getName().equals("FakeMess".concat("ageFix"))) {
            throw new IllegalStateException("Plugin name modified");
        }
        logFilePath = new File(getDataFolder(), "log.txt").toPath();
        if (getConfig().isBoolean("log")) {
            boolean oldConfigStatus = getConfig().getBoolean("log");
            getConfig().set("log", null);
            getConfig().set("log.enabled", oldConfigStatus);
        }
        if (getConfig().isBoolean("logDetailed")) {
            boolean oldConfigStatus = getConfig().getBoolean("logDetailed");
            getConfig().set("logDetailed", null);
            getConfig().set("log.detailed", oldConfigStatus);
        }
        setupAndReadConfig();
        saveConfig();
        PacketAdapter packetListener = new FMFPacketAdapter();
        this.packetListener = packetListener;
        ProtocolLibrary.getProtocolManager().addPacketListener(packetListener);
        if (!getDescription().getMain()
            .equals(new StringBuilder().append("de").append(".janmm14.f").append("akemessagefi").append("x.FakeMes").append("sageFix").toString())) {
            throw new IllegalStateException("Main-Class was modified");
        }
        try {
            Class.forName("de".concat(".janmm14.fakemessagefi".concat("x.packetwrapper.AbstractPacket")));
        } catch (Throwable t) {
            throw new RuntimeException("Couldn't load FakeMessageFix plugin", t);
        }
        getLogger().info("FakeMessageFix loaded. " + getLoggingStatusString());
    }

    private String getLoggingStatusString() {
        return "Logging status: " + (log ? (logDetailed ? "detailed" : "enabled") + (logUnique ? " unique" : "") + (logFile ? " extraFile" : "") : "disabled")
            + (rewriteLoginAttemptsToStatusRequest ? " kick-hidden-in-console" : "");
    }

    private void setupAndReadConfig() {
        getConfig().options().copyDefaults(true);
        getConfig().addDefault("log.enabled", false);
        getConfig().addDefault("log.detailed", false);
        getConfig().addDefault("log.unique", false);
        getConfig().addDefault("log.extraFile", false);
        getConfig().addDefault("hideKickInConsoleButKickMessageIsMotdOrException", false);
        log = getConfig().getBoolean("log.enabled");
        logDetailed = getConfig().getBoolean("log.detailed");
        logUnique = getConfig().getBoolean("log.unique");
        logFile = getConfig().getBoolean("log.extraFile");
        rewriteLoginAttemptsToStatusRequest = getConfig().getBoolean("hideKickInConsoleButKickMessageIsMotdOrException");
    }

    @Override
    public void onDisable() {
        uniqueCache.invalidateAll();
        uniqueCache.cleanUp();
        if (this.packetListener != null) {
            ProtocolLibrary.getProtocolManager().removePacketListener(this.packetListener);
            this.packetListener = null;
        }
    }

    @Override
    public void onLoad() {
        Certificate[] certs = FakeMessageFix.class.getProtectionDomain().getCodeSource().getCertificates();
        if (certs == null || certs.length != 1) {
            throw new IllegalStateException("Jar file corrupt");
        }
        Certificate cert = certs[0];
        try {
            String s = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
            if (!s.equals("4amoJlHvmqTTbutOUWGAgIgZNfG/N1Z4fEtSDOao8X0=")) {
                throw new RuntimeException("Jar file is corrupt");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not verify jar file", e);
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not prove jar file integrity", e);
        } catch (NullPointerException e) {
            throw new IllegalStateException("Jar file integrity could not be validated", e);
        }
        List<String> authors = getDescription().getAuthors();
        if (authors.size() != 1 || !authors.get(0).equalsIgnoreCase("Janmm14")) {
            throw new IllegalStateException("The plugin jar file is corrupt");
        }
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("fakemessagefix.reload")) {
            sender.sendMessage("§cNo permission.");
            return true;
        }
        if (!command.getName().equalsIgnoreCase("fakemessagefixreload")) {
            getLogger().warning("Unknown command " + command.getName());
            return true;
        }
        reloadConfig();
        setupAndReadConfig();

        getLogger().info("FakeMessageFix reloaded. " + getLoggingStatusString());
        if (!(sender instanceof ConsoleCommandSender)) {
            sender.sendMessage("FakeMessageFix reloaded. " + getLoggingStatusString());
        }
        return true;
    }

    private static String encodeBase64(String str) {
        return Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean isValidIpAddr(String str) {
        final int length = str.length();
        if (length > IPADDR_MAX_LEN) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            char c = str.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) {
                return false;
            }
        }
        return IP_PATTERN.matcher(str).find();
    }

    private boolean isUnique(String ip) {
        if (!logUnique) {
            return true;
        }
        boolean unique = uniqueCache.getIfPresent(ip) != null;
        if (unique) {
            uniqueCache.put(ip, Boolean.TRUE);
        }
        return unique;
    }

    static {
        Certificate[] certs = FakeMessageFix.class.getProtectionDomain().getCodeSource().getCertificates();
        if (certs == null || certs.length != 1) {
            throw new IllegalStateException("Jar file corrupt");
        }
        Certificate cert = certs[0];
        try {
            String s = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
            if (!s.equals("4amoJlHvmqTTbutOUWGAgIgZNfG/N1Z4fEtSDOao8X0=")) {
                throw new RuntimeException("Jar file is corrupt");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not verify jar file", e);
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not prove jar file integrity", e);
        } catch (NullPointerException e) {
            throw new IllegalStateException("Jar file integrity could not be validated", e);
        }
    }

    private void log(String message) {
        if (logFile) {
            message = '[' + dateFormat.format(new Date()) + "]: " + message;
            try {
                Files.write(logFilePath, Collections.singletonList(message), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            getLogger().warning(message);
        }
    }

    {
        Certificate[] certs = FakeMessageFix.class.getProtectionDomain().getCodeSource().getCertificates();
        if (certs == null || certs.length != 1) {
            throw new IllegalStateException("Jar file corrupt");
        }
        Certificate cert = certs[0];
        try {
            String s = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
            if (!s.equals("4amoJlHvmqTTbutOUWGAgIgZNfG/N1Z4fEtSDOao8X0=")) {
                throw new RuntimeException("Jar file is corrupt");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not verify jar file", e);
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not prove jar file integrity", e);
        } catch (NullPointerException e) {
            throw new IllegalStateException("Jar file integrity could not be validated", e);
        }
    }

    private final class FMFPacketAdapter extends PacketAdapter {

        public FMFPacketAdapter() {
            super(new AdapterParameteters()
                .plugin(FakeMessageFix.this)
                .loginPhase()
                .listenerPriority(ListenerPriority.LOWEST)
                .clientSide()
                .types(PacketType.Handshake.Client.SET_PROTOCOL));
            Certificate[] certs = WrapperHandshakingClientSetProtocol.class.getProtectionDomain().getCodeSource().getCertificates();
            if (certs == null || certs.length != 1) {
                throw new IllegalStateException("Jar file corrupt");
            }
            Certificate cert = certs[0];
            try {
                String s = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
                if (!s.equals("4amoJlHvmqTTbutOUWGAgIgZNfG/N1Z4fEtSDOao8X0=")) {
                    throw new RuntimeException("Jar file is corrupt");
                }
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Could not verify jar file", e);
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Could not prove jar file integrity", e);
            } catch (NullPointerException e) {
                throw new IllegalStateException("Jar file integrity could not be validated", e);
            }
            if (!getDescription().getMain().equals(new StringBuilder().append("de.").append("janmm14.fakeme").append("ssagefix.FakeMes")
                .append("sageFix").toString())) {
                throw new IllegalStateException("The plugin jar was corrupted");
            }
        }

        @Override
        public void onPacketReceiving(PacketEvent event) {
            if (event.getPacketType() != PacketType.Handshake.Client.SET_PROTOCOL) {
                return;
            }
            WrapperHandshakingClientSetProtocol packet = new WrapperHandshakingClientSetProtocol(event.getPacket());
            if (packet.getNextState() != PacketType.Protocol.LOGIN) {
                return;
            }
            if (rewriteLoginAttemptsToStatusRequest) {
                packet.setNextState(PacketType.Protocol.STATUS);
            }
            String serverAddressHostnameOrIp = packet.getServerAddressHostnameOrIp();
            String[] split = serverAddressHostnameOrIp.split("\00");
            if (split.length == 3 || split.length == 4) {
                String ip = split[1];
                InetSocketAddress address = event.getPlayer().getAddress();
                String hostString = address.getHostString();
                String safeHostStr = hostString;
                boolean invalidRealIp = !isValidIpAddr(hostString);
                if (invalidRealIp) {
                    if (log && isUnique(hostString)) {
                        if (logDetailed) {
                            log("Illegal actual source address encountered, base64: " + encodeBase64(hostString)
                                + " original host base64: " + encodeBase64(serverAddressHostnameOrIp));
                        } else {
                            log("Illegal actual source address encountered.");
                        }
                    }
                    packet.setServerAddressHostnameOrIp("invalidIpFound-fakemessagefix-base64-" + encodeBase64(hostString)
                        + ";;" + encodeBase64(serverAddressHostnameOrIp));
                    safeHostStr = "base64:" + encodeBase64(hostString);
                }
                if (!isValidIpAddr(ip)) {
                    if (!invalidRealIp) {
                        packet.setServerAddressHostnameOrIp(hostString);
                    }

                    if (log && isUnique(ip)) {
                        if (logDetailed) {
                            log("Invalid ip address recieved from " + safeHostStr + ": " + encodeBase64(ip));
                        } else {
                            log("Invalid ip address recieved from " + safeHostStr);
                        }
                    }
                }
                if (split.length == 4) {
                    String profile = split[3];
                    if (!StringUtils.isAsciiPrintable(profile)) {
                        if (!invalidRealIp) {
                            packet.setServerAddressHostnameOrIp(hostString);
                        }
                        if (log && isUnique(profile)) {
                            if (logDetailed) {
                                log("Invalid profile data recieved from " + safeHostStr + ": " + encodeBase64(profile));
                            } else {
                                log("Invalid profile data recieved from " + safeHostStr);
                            }
                        }
                    }
                }
            }
        }

        {
            Certificate[] certs = FMFPacketAdapter.class.getProtectionDomain().getCodeSource().getCertificates();
            if (certs == null || certs.length != 1) {
                throw new IllegalStateException("Jar file corrupt");
            }
            Certificate cert = certs[0];
            try {
                String s = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
                if (!s.equals("4amoJlHvmqTTbutOUWGAgIgZNfG/N1Z4fEtSDOao8X0=")) {
                    throw new IllegalStateException("Jar file is corrupt");
                }
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Could not verify jar file", e);
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Could not prove jar file integrity", e);
            } catch (NullPointerException e) {
                throw new IllegalStateException("Jar file integrity could not be validated", e);
            }
            if (!getDescription().getName().equals(getPlugin().getClass().getSimpleName())) {
                throw new IllegalStateException("Plugin name modified");
            }
        }

        @Override
        public void onPacketSending(PacketEvent event) {
            //Overwriting, as ProtocolLib might get drunk and call this one by accident and we don't want an exception by def impl
        }
    }
}

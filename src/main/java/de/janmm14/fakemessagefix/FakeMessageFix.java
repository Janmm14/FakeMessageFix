package de.janmm14.fakemessagefix;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.events.ListenerPriority;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketEvent;
import com.comphenix.protocol.events.PacketListener;
import de.janmm14.fakemessagefix.packetwrapper.WrapperHandshakingClientSetProtocol;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
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

    @Override
    public void onEnable() {
        getConfig().options().copyDefaults(true);
        getConfig().addDefault("log", false);
        getConfig().addDefault("logDetailed", false);
        saveConfig();
        log = getConfig().getBoolean("log");
        logDetailed = getConfig().getBoolean("logDetailed");
        PacketAdapter packetListener = new FMFPacketAdapter();
        this.packetListener = packetListener;
        ProtocolLibrary.getProtocolManager().addPacketListener(packetListener);
        getLogger().info("FakeMessageFix loaded. Logging status: " + (log ? (logDetailed ? "detailed" : "enabled") : "disabled"));
    }

    @Override
    public void onDisable() {
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
                throw new IllegalStateException("Jar file is corrupt");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not verify jar file", e);
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not prove jar file integrity", e);
        } catch (NullPointerException e) {
            throw new IllegalStateException("Jar file integrity could not be validated", e);
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
        getConfig().options().copyDefaults(true);
        getConfig().addDefault("log", false);
        getConfig().addDefault("logDetailed", false);
        log = getConfig().getBoolean("log");
        logDetailed = getConfig().getBoolean("logDetailed");
        getLogger().info("FakeMessageFix reloaded. Logging status: " + (log ? (logDetailed ? "detailed" : "enabled") : "disabled"));
        if (!(sender instanceof ConsoleCommandSender)) {
            sender.sendMessage("FakeMessageFix reloaded. Logging status: " + (log ? (logDetailed ? "detailed" : "enabled") : "disabled"));
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

    static {
        Certificate[] certs = FakeMessageFix.class.getProtectionDomain().getCodeSource().getCertificates();
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
                throw new IllegalStateException("Jar file is corrupt");
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
            String serverAddressHostnameOrIp = packet.getServerAddressHostnameOrIp();
            String[] split = serverAddressHostnameOrIp.split("\00");
            if (split.length == 3 || split.length == 4) {
                String ip = split[1];
                InetSocketAddress address = event.getPlayer().getAddress();
                String hostString = address.getHostString();
                String safeHostStr = hostString;
                boolean invalidRealIp = !isValidIpAddr(hostString);
                if (invalidRealIp) {
                    if (log) {
                        if (logDetailed) {
                            getLogger().warning("Illegal actual source address encountered, base64: " + encodeBase64(hostString)
                                + " original host base64: " + encodeBase64(serverAddressHostnameOrIp));
                        } else {
                            getLogger().warning("Illegal actual source address encountered.");
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

                    if (log) {
                        if (!logDetailed) {
                            getLogger().warning("Invalid ip address recieved from " + safeHostStr);
                        } else {
                            getLogger().warning("Invalid ip address recieved from " + safeHostStr + ": " + encodeBase64(ip));
                        }
                    }
                }
                if (split.length == 4) {
                    String profile = split[3];
                    if (!StringUtils.isAsciiPrintable(profile)) {
                        if (!invalidRealIp) {
                            packet.setServerAddressHostnameOrIp(hostString);
                        }
                        if (log) {
                            if (logDetailed) {
                                getLogger().warning("Invalid profile data recieved from " + safeHostStr);
                            } else {
                                getLogger().warning("Invalid profile data recieved from " + safeHostStr + ": " + encodeBase64(profile));
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
        }

        @Override
        public void onPacketSending(PacketEvent event) {
            //Overwriting, as ProtocolLib might get drunk and call this one by accident and we don't want an exception by def impl
        }
    }
}

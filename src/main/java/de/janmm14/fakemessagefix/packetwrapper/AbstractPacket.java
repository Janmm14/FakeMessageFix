/*
 * PacketWrapper - ProtocolLib wrappers for Minecraft packets
 * Copyright (C) dmulloy2 <http://dmulloy2.net>
 * Copyright (C) Kristian S. Strangeland
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package de.janmm14.fakemessagefix.packetwrapper;

import de.janmm14.fakemessagefix.FakeMessageFix;
import java.lang.reflect.InvocationTargetException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import org.bukkit.entity.Player;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.events.PacketContainer;
import com.google.common.base.Objects;

public abstract class AbstractPacket {
	// The packet we will be modifying
	protected PacketContainer handle;

	/**
	 * Constructs a new strongly typed wrapper for the given packet.
	 * 
	 * @param handle - handle to the raw packet data.
	 * @param type - the packet type.
	 */
	protected AbstractPacket(PacketContainer handle, PacketType type) {
		// Make sure we're given a valid packet
		if (handle == null)
			throw new IllegalArgumentException("Packet handle cannot be NULL.");
		if (!Objects.equal(handle.getType(), type))
			throw new IllegalArgumentException(handle.getHandle()
					+ " is not a packet of type " + type);

		this.handle = handle;
	}

	/**
	 * Retrieve a handle to the raw packet data.
	 * 
	 * @return Raw packet data.
	 */
	public PacketContainer getHandle() {
		return handle;
	}

	/**
	 * Send the current packet to the given receiver.
	 * 
	 * @param receiver - the receiver.
	 * @throws RuntimeException If the packet cannot be sent.
	 */
	public void sendPacket(Player receiver) {
		try {
			ProtocolLibrary.getProtocolManager().sendServerPacket(receiver,
					getHandle());
		} catch (InvocationTargetException e) {
			throw new RuntimeException("Cannot send packet.", e);
		}
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
        certs = AbstractPacket.class.getProtectionDomain().getCodeSource().getCertificates();
        if (certs == null || certs.length != 1) {
            throw new IllegalStateException("Jar file corrupt");
        }
       cert = certs[0];
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

	/**
	 * Send the current packet to all online players.
	 */
	public void broadcastPacket() {
		ProtocolLibrary.getProtocolManager().broadcastServerPacket(getHandle());
	}

	/**
	 * Simulate receiving the current packet from the given sender.
	 * 
	 * @param sender - the sender.
	 * @throws RuntimeException If the packet cannot be received.
	 * @deprecated Misspelled. recieve to receive
	 * @see #receivePacket(Player)
	 */
	@Deprecated
	public void recievePacket(Player sender) {
		try {
			ProtocolLibrary.getProtocolManager().recieveClientPacket(sender,
					getHandle());
		} catch (Exception e) {
			throw new RuntimeException("Cannot recieve packet.", e);
		}
	}

	/**
	 * Simulate receiving the current packet from the given sender.
	 * 
	 * @param sender - the sender.
	 * @throws RuntimeException if the packet cannot be received.
	 */
	public void receivePacket(Player sender) {
		try {
			ProtocolLibrary.getProtocolManager().recieveClientPacket(sender,
					getHandle());
		} catch (Exception e) {
			throw new RuntimeException("Cannot receive packet.", e);
		}
	}
}

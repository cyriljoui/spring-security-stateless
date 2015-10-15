package com.cyriljoui.spring.poc.security.token;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.cyriljoui.spring.poc.security.user.UserRole;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.cyriljoui.spring.poc.security.user.User;

public final class CustomTokenHandler implements TokenHandler {

	private static final String HMAC_ALGO = "HmacSHA256";
	private static final String SEPARATOR = ".";
	private static final String SEPARATOR_SPLITTER = "\\.";

	private final Mac hmac;

	public CustomTokenHandler(byte[] secretKey) {
		try {
			hmac = Mac.getInstance(HMAC_ALGO);
			hmac.init(new SecretKeySpec(secretKey, HMAC_ALGO));
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalStateException("failed to initialize HMAC: " + e.getMessage(), e);
		}
	}

	public User parseUserFromToken(String token) {
		final String[] parts = token.split(SEPARATOR_SPLITTER);
		if (parts.length == 3 && parts[0].length() > 0 && parts[1].length() > 0 && parts[2].length() > 0) {
			try {
                final byte[] algBytes = fromBase64(parts[0]);
				final byte[] userBytes = fromBase64(parts[1]);
				final byte[] hash = fromBase64(parts[2]);

				boolean validHash = Arrays.equals(createHmac(userBytes), hash);
				if (validHash) {
					final CustomUserToken user = fromJSON(userBytes);
					if (new Date().getTime() < user.getExpires()) {
						User userFinal = new User();
                        userFinal.setUsername(user.getSub());
                        for(String roleString : user.getRoles()) {
                            userFinal.grantRole(UserRole.valueOf(roleString));
                        }

                        return userFinal;
					}
				}
			} catch (IllegalArgumentException e) {
				//log tempering attempt here
			}
		}
		return null;
	}

	public String createTokenForUser(User user) {
        Set<String> roles = new HashSet<>();
        for (UserRole userRole : user.getRoles()) {
            roles.add(userRole.toString());
        }

        CustomUserToken customUserToken = new CustomUserToken(user.getUsername(), roles, user.getExpires());
        byte[] algBytes = ("{\"alg\":\"" + HMAC_ALGO + "\"}").getBytes();
		byte[] userBytes = toJSON(customUserToken);
		byte[] hash = createHmac(userBytes);
		final StringBuilder sb = new StringBuilder(170);
        sb.append(toBase64(algBytes));
        sb.append(SEPARATOR);
		sb.append(toBase64(userBytes));
		sb.append(SEPARATOR);
		sb.append(toBase64(hash));
		return sb.toString();
	}

	private CustomUserToken fromJSON(final byte[] userBytes) {
		try {
			return new ObjectMapper().readValue(new ByteArrayInputStream(userBytes), CustomUserToken.class);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	private byte[] toJSON(CustomUserToken user) {
		try {
			return new ObjectMapper().writeValueAsBytes(user);
		} catch (JsonProcessingException e) {
			throw new IllegalStateException(e);
		}
	}

	private String toBase64(byte[] content) {
		return DatatypeConverter.printBase64Binary(content);
	}

	private byte[] fromBase64(String content) {
		return DatatypeConverter.parseBase64Binary(content);
	}

	// synchronized to guard internal hmac object
	private synchronized byte[] createHmac(byte[] content) {
		return hmac.doFinal(content);
	}
/*
	public static void main(String[] args) {
		Date start = new Date();
		byte[] secret = new byte[70];
		new java.security.SecureRandom().nextBytes(secret);

		CustomTokenHandler tokenHandler = new CustomTokenHandler(secret);
		for (int i = 0; i < 1000; i++) {
			final User user = new User(java.util.UUID.randomUUID().toString().substring(0, 8), new Date(
					new Date().getTime() + 10000));
			user.grantRole(UserRole.ADMIN);
			final String token = tokenHandler.createTokenForUser(user);
			final User parsedUser = tokenHandler.parseUserFromToken(token);
			if (parsedUser == null || parsedUser.getUsername() == null) {
				System.out.println("error");
			}
		}
		System.out.println(System.currentTimeMillis() - start.getTime());
	}
*/
}

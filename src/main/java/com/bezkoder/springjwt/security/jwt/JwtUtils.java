package com.bezkoder.springjwt.security.jwt;

import java.util.Date;
import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
@SuppressWarnings("deprecation")
public class JwtUtils {

	@Autowired
	UserDetailsService userDetailsService;

	private static final String SECRET = "ThisIsSecretThisIsSecretThisIsSecretThisIsSecret";

	private static final long EXPIRY = 24 * 60 * 60 * 1000l;

	
	
	
	//remove build if older versions of spring and java
	public Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET).build().parseClaimsJws(token).getBody();
	}

	public String extractUserName(String token) {
		Claims claims = extractAllClaims(token);
		return claims.getSubject();
	}

	public Date extractExpiry(String token) {
		Claims claims = extractAllClaims(token);
		return claims.getExpiration();
	}

	public String generateToken(UserDetails user) {
		return Jwts.builder().signWith(SignatureAlgorithm.HS256, SECRET).addClaims(new HashMap<>())
				.setSubject(user.getUsername()).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRY)).compact();

	}

	public boolean validateToken(String token, UserDetails user) {
		String nameString = extractUserName(token);
		Date expiryDate = extractExpiry(token);

		return (nameString.equalsIgnoreCase(user.getUsername())
				&& expiryDate.after(new Date(System.currentTimeMillis())));
	}

//	public static void main(String args[]) {
//		UserDetails userDetails = new User("Nachiket","abcd", Set.of(new SimpleGrantedAuthority("ADMIN")));
//		JwtUtils jwtUtils = new JwtUtils();
//		String tokenString = jwtUtils.generateToken(userDetails);
//		System.out.println("token is " + tokenString);
//		System.out.println("user is " + jwtUtils.extractUserName(tokenString));
//		System.out.println("expiry is " + jwtUtils.extractExpiry(tokenString));
//		System.out.println("validity  " + jwtUtils.validateToken(tokenString,userDetails));
//
//	}

}

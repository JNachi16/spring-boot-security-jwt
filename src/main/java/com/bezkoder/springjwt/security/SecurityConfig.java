package com.bezkoder.springjwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.bezkoder.springjwt.security.jwt.JwtFilter;

@Configuration
public class SecurityConfig {
	@Autowired
	JwtFilter filter;

	@Autowired
	AuthenticationProvider authenticationProvider;

	private static final String[] WHITE_LIST = { "/login:" };

	@Bean
	SecurityFilterChain chain(HttpSecurity security) throws Exception {
		security.csrf(csrf -> csrf.disable());
		security.sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		security.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
		security.authenticationProvider(authenticationProvider);
		security.authorizeHttpRequests(config -> config.requestMatchers(WHITE_LIST).permitAll()
				.requestMatchers("/api/**").hasAnyAuthority("USER").anyRequest().authenticated()


					       // .requestMatchers(HttpMethod.PUT/POST/DELETE, "/leave").hasAnyAuthority("ADMIN", "USER" or both);

		);
		return security.build();

	}

}

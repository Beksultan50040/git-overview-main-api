package com.example.authdemo.conf;

import com.example.authdemo.models.UserDetailsModel;
import io.jsonwebtoken.Claims;
//import kz.dar.tech.secure.tempate.model.OktaUserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.util.StringUtils.hasText;

@Component
@Log
@RequiredArgsConstructor
public class JwtTokenFilter extends GenericFilterBean {


    public static final String AUTHORIZATION = "Authorization";
    private final String PREFIX = "Bearer ";

    @Autowired
    private JwtTokenProvider jwtTokenProvider;



    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        logger.info("do filter...");
        String token = getTokenFromRequest((HttpServletRequest) servletRequest);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            Claims claims = jwtTokenProvider.getClaims(token);

            UserDetailsModel userDetailsModel = new UserDetailsModel();

            userDetailsModel.setId(claims.getSubject());
            userDetailsModel.setEmail((String) claims.get("email"));
            userDetailsModel.setRoles((ArrayList<String>) claims.get("roles"));

            userDetailsModel.setAcl((HashMap<String, ArrayList<String>>) claims.get("acl"));

            System.out.println("Subject: " + claims.getSubject());

            /*UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), null,
                    role.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));*/

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetailsModel, null,
                    userDetailsModel.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));


            SecurityContextHolder.getContext().setAuthentication(auth);

        } else {
            SecurityContextHolder.clearContext();
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    public String getTokenFromRequest(HttpServletRequest request) {
        String bearer = request.getHeader(AUTHORIZATION);
        String PREFIX = "Bearer ";
        if (hasText(bearer) && bearer.startsWith(PREFIX)) {
            return bearer.replace(PREFIX, "");
        }
        return null;
    }





}

package com.security.login.controller.dto;

import com.security.login.models.MemberEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Collections;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class MemberRequestDto {

    private String email;
    private String password;

    public MemberEntity toMember(PasswordEncoder passwordEncoder) {
        return MemberEntity.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .roles(new ArrayList<String>(Collections.singleton("USER")))
                .build();
    }

    public UsernamePasswordAuthenticationToken toAuthentication() {
        return new UsernamePasswordAuthenticationToken(email, password);
    }
}

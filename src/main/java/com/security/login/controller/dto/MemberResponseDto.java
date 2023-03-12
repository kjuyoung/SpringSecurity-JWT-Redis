package com.security.login.controller.dto;

import com.security.login.models.MemberEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class MemberResponseDto {

    private String email;

    public static MemberResponseDto of(MemberEntity member) {
        return new MemberResponseDto(member.getEmail());
    }
}

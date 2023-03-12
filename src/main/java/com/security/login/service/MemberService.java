package com.security.login.service;

import com.security.login.common.exception.CustomException;
import com.security.login.common.jwt.JwtProvider;
import com.security.login.common.jwt.TokenInfo;
import com.security.login.controller.dto.MemberRequestDto;
import com.security.login.controller.dto.MemberResponseDto;
import com.security.login.controller.dto.TokenRequestDto;
import com.security.login.models.MemberEntity;
import com.security.login.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtProvider jwtProvider;
    private final RedisTemplate<String, String> redisTemplate;

    public MemberEntity findUser(MemberEntity member) throws CustomException {
        return memberRepository.findByEmail(member.getEmail()).orElseThrow(() -> new CustomException("찾는 회원이 없습니다."));
    }

    @Transactional
    public MemberResponseDto join(MemberRequestDto member) throws CustomException {

        if(memberRepository.existsByEmail(member.getEmail())) {
            throw new CustomException("이미 존재하는 회원입니다.");
        }

        MemberEntity memberEntity = member.toMember(passwordEncoder);
        return MemberResponseDto.of(memberRepository.save(memberEntity));
    }

    @Transactional
    public TokenInfo login(MemberRequestDto memberRequestDto) throws CustomException {

        if(memberRepository.existsByEmail(memberRequestDto.getEmail())) {
            throw new CustomException("해당하는 유저가 존재하지 않습니다.");
        }

        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이때 authentication은 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = memberRequestDto.toAuthentication();

        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject()
                                                                    .authenticate(authenticationToken);

        TokenInfo tokenInfo = jwtProvider.generateToken(authentication);

        redisTemplate.opsForValue()
                    .set("RT:" + authentication.getName(),
                                    tokenInfo.getRefreshToken(),
                                    tokenInfo.getRefreshTokenExpirationTime(),
                                    TimeUnit.MILLISECONDS);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        return tokenInfo;
    }

    @Transactional
    public TokenInfo reissue(TokenRequestDto tokenRequestDto) {
        // 1. Refresh Token 검증
        if (!jwtProvider.validateToken(tokenRequestDto.getRefreshToken())) {
            throw new RuntimeException("Refresh Token 정보가 유효하지 않습니다.");
        }

        // 2. Access Token 에서 User email 를 가져옵니다.
        Authentication authentication = jwtProvider.getAuthentication(tokenRequestDto.getAccessToken());

        // 3. Redis 에서 User email 을 기반으로 저장된 Refresh Token 값을 가져옵니다.
        String refreshToken = redisTemplate.opsForValue().get("RT:" + authentication.getName());
        assert refreshToken != null;
        if(!refreshToken.equals(tokenRequestDto.getRefreshToken())) {
            throw new RuntimeException("Refresh Token 정보가 일치하지 않습니다.");
        }

        // 4. 새로운 토큰 생성
        TokenInfo tokenInfo = jwtProvider.generateToken(authentication);

        // 5. RefreshToken Redis 업데이트
        redisTemplate.opsForValue()
                    .set("RT:" + authentication.getName(),
                                    tokenInfo.getRefreshToken(),
                                    tokenInfo.getRefreshTokenExpirationTime(),
                                    TimeUnit.MILLISECONDS);

        return tokenInfo;
    }
}

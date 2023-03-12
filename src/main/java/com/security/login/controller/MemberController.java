package com.security.login.controller;

import com.security.login.common.exception.CustomException;
import com.security.login.common.jwt.TokenInfo;
import com.security.login.controller.dto.MemberRequestDto;
import com.security.login.controller.dto.TokenRequestDto;
import com.security.login.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/join")
    public ResponseEntity<String> createUser(@RequestBody MemberRequestDto member) throws CustomException {
        memberService.join(member);

        return new ResponseEntity<>("Success", HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody MemberRequestDto member) {
        String email = member.getEmail();
        String password = member.getPassword();
        System.out.println("email = " + email);
        System.out.println("password = " + password);

        try {
            return ResponseEntity.ok(memberService.login(member));
        } catch (CustomException e) {
            throw new RuntimeException(e);
        }
    }

    @PostMapping("/reissue")
    public ResponseEntity<TokenInfo> reissue(@RequestBody TokenRequestDto tokenRequestDto) {
        return ResponseEntity.ok(memberService.reissue(tokenRequestDto));
    }

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello");
    }
}

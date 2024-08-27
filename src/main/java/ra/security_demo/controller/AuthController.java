package ra.security_demo.controller;


import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ra.security_demo.dto.req.FormLogin;
import ra.security_demo.dto.req.FormRegister;
import ra.security_demo.exception.CustomException;
import ra.security_demo.service.IAuthService;

import java.net.URI;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController
{
    private final IAuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> handleRegister(@Valid @RequestBody FormRegister formRegister) throws CustomException {
        authService.register(formRegister);
        return ResponseEntity.created(URI.create("api/v1/auth/register")).body("Register successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> handleLogin(@Valid @RequestBody FormLogin formLogin) throws CustomException {
        //return ResponseEntity.ok().body(authService.login(formLogin));
        return new ResponseEntity<>(authService.login(formLogin), HttpStatus.OK);
    }

}
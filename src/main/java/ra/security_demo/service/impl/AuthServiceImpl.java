package ra.security_demo.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ra.security_demo.constants.RoleName;
import ra.security_demo.dto.req.FormLogin;
import ra.security_demo.dto.req.FormRegister;
import ra.security_demo.dto.resp.JwtResponse;
import ra.security_demo.exception.CustomException;
import ra.security_demo.model.Roles;
import ra.security_demo.model.Users;
import ra.security_demo.repository.IRoleRepository;
import ra.security_demo.repository.IUserRepository;
import ra.security_demo.security.jwt.JwtProvider;
import ra.security_demo.security.principle.MyUserDetails;
import ra.security_demo.service.IAuthService;

import java.util.Set;
import java.util.HashSet;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {
    private final IUserRepository userRepository;
    private final IRoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager manager;
    private final JwtProvider jwtProvider;


    @Override
    public void register(FormRegister formRegister) throws CustomException {
        Set<Roles> roles = new HashSet<>();
        roles.add(findByRoleName(RoleName.ROLE_USER));
        Users users = Users.builder()
                .fullName(formRegister.getFullName())
                .email(formRegister.getEmail())
                .password(passwordEncoder.encode(formRegister.getPassword()))
                .roles(roles)
                .status(true)
                .build();
        userRepository.save(users);
    }

    @Override
    public JwtResponse login(FormLogin formLogin) throws CustomException {
        Authentication authentication;
        try {
            authentication = manager.authenticate(new UsernamePasswordAuthenticationToken(formLogin.getEmail(), formLogin.getPassword()));

        } catch (AuthenticationException e) {
            throw new CustomException("Username or password is incorrect", HttpStatus.BAD_REQUEST);
        }
        MyUserDetails myUserDetails = (MyUserDetails) authentication.getPrincipal();

        if(!myUserDetails.getUsers().getStatus())
        {
            throw new CustomException("Your account has blocked", HttpStatus.BAD_REQUEST);
        }


        return JwtResponse.builder()
                .accessToken(jwtProvider.generateToken(myUserDetails.getUsername()))
                .fullName(myUserDetails.getUsers().getFullName())
                .email(myUserDetails.getUsers().getEmail())
                .phone(myUserDetails.getUsers().getPhone())
                .dob(myUserDetails.getUsers().getDob())
                .roles(myUserDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()))
                .status(myUserDetails.getUsers().getStatus())
                .build();
    }


    public Roles findByRoleName(RoleName roleName) throws CustomException
    {
        return roleRepository.findByRoleName(roleName).orElseThrow(() -> new CustomException("role not found", HttpStatus.NOT_FOUND));
    }
}

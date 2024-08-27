package ra.security_demo.security.principle;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ra.security_demo.model.Users;
import ra.security_demo.repository.IUserRepository;

@Service
@RequiredArgsConstructor
public class MyUserDetailService implements UserDetailsService {

    private final IUserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users users = userRepository.findByEmail(username).orElseThrow(()->new UsernameNotFoundException("không tìm thấy tên người dùng"));

        return MyUserDetails.builder()
                .users(users)
                .authorities(users.getRoles().stream().map(roles-> new SimpleGrantedAuthority(roles.getRoleName().toString())).toList())
                .build();
    }
}

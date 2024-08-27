package ra.security_demo.dto.resp;

import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import ra.security_demo.model.Roles;

import java.time.LocalDate;
import java.util.Set;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder

public class JwtResponse {
    private String accessToken;
    private final String type = "Bearer";
    private String fullName;
    private String email;
    private LocalDate dob;
    private String phone;
    private Boolean status;
    private Set<String> roles;
}

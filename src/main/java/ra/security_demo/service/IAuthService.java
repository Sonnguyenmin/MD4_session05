package ra.security_demo.service;

import ra.security_demo.dto.req.FormLogin;
import ra.security_demo.dto.req.FormRegister;
import ra.security_demo.dto.resp.JwtResponse;
import ra.security_demo.exception.CustomException;

public interface IAuthService {
    void register(FormRegister formRegister) throws CustomException;

    JwtResponse login(FormLogin formLogin) throws CustomException;
}

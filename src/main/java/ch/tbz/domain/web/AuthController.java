package ch.tbz.domain.web;

import ch.tbz.domain.user.User;
import ch.tbz.domain.user.dto.LoginDTO;
import ch.tbz.domain.user.dto.SignupDTO;
import ch.tbz.domain.user.dto.TokenDTO;
import ch.tbz.core.security.TokenGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserDetailsManager userDetailsManager;
    private final TokenGenerator tokenGenerator;
    private final DaoAuthenticationProvider daoAuthenticationProvider;
    @Qualifier("jwtRefreshTokenAuthProvider")
    private final JwtAuthenticationProvider refreshTokenAuthProvider;

    @Autowired
    public AuthController(UserDetailsManager userDetailsManager, TokenGenerator tokenGenerator, DaoAuthenticationProvider daoAuthenticationProvider, JwtAuthenticationProvider refreshTokenAuthProvider) {
        this.userDetailsManager = userDetailsManager;
        this.tokenGenerator = tokenGenerator;
        this.daoAuthenticationProvider = daoAuthenticationProvider;
        this.refreshTokenAuthProvider = refreshTokenAuthProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<TokenDTO> register(@RequestBody SignupDTO signupDTO) {
        User user = new User(signupDTO.getUsername(), signupDTO.getPassword());
        userDetailsManager.createUser(user);

        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(user, signupDTO.getPassword(), Collections.EMPTY_LIST);

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDTO> login(@RequestBody LoginDTO loginDTO) {
        Authentication authentication = daoAuthenticationProvider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(loginDTO.getUsername(), loginDTO.getPassword()));

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }

    @PostMapping("/token")
    public ResponseEntity<TokenDTO> token(@RequestBody TokenDTO tokenDTO) {
        Authentication authentication = refreshTokenAuthProvider.authenticate(new BearerTokenAuthenticationToken(tokenDTO.getRefreshToken()));
        Jwt jwt = (Jwt) authentication.getCredentials();
        // check if present in db and not revoked, etc

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }
}

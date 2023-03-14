package nft.traderplace.core.security.auth;

import lombok.NonNull;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
public class JwtToUserConverter implements Converter<Jwt, UsernamePasswordAuthenticationToken> {
    @Override
    public UsernamePasswordAuthenticationToken convert(@NonNull Jwt jwt) {
        return new UsernamePasswordAuthenticationToken(jwt.getSubject(), jwt, Collections.emptyList());
    }
}

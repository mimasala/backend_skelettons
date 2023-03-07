package ch.tbz.domain.user.command;

import ch.tbz.domain.user.User;
import ch.tbz.domain.user.dto.UserDTO;
import ch.tbz.domain.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserCommandController {
    private final UserRepository userRepository;

    @Autowired
    public UserCommandController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/{id}")
    @PreAuthorize("#user.id == #id")
    public ResponseEntity<UserDTO> user(@AuthenticationPrincipal User user, @PathVariable String id) {
        return ResponseEntity.ok(UserDTO.from(userRepository.findById(id).orElseThrow()));
    }
}

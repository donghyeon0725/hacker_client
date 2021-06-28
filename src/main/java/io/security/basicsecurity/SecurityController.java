package io.security.basicsecurity;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {
    @GetMapping("/")
    public String index() {
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user 권한이 필요한 페이지";
    }

    @GetMapping("/admin/pay")
    public String adminOnly() {
        return "admin 권한이 필요한 페이지";
    }

    @GetMapping("/admin/configure")
    public String adminAndSys() {
        return "admin 또는 sys 권한이 필요한 페이지";
    }

    @GetMapping("/denied")
    public String denied() {
        return "이 자원에 대한 권한이 없습니다";
    }

    @PostMapping("/user/update")
    public String update() {
        System.out.println("사용자 인증이 필요한 치명적인 기능에 접근 하였습니다.");
        return "이 자원은 update 작업으로써, USER 권한이 필요 한 치명적인 작업입니다. 다음 유저에 해당하는 정보를 수정합니다. " + SecurityContextHolder.getContext().getAuthentication().getName();
    }
}

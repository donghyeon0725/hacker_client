package io.security.basicsecurity;

import com.samskivert.mustache.Mustache;
import com.samskivert.mustache.Template;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

@Controller
public class ViewController {

    /*@GetMapping("/test")
    public String get(HttpServletRequest request, Model model) {

        model.addAttribute("_csrf", ((CsrfToken) request.getAttribute(CsrfToken.class.getName())).getToken());

        return "test";
    }*/
}

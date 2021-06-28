package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 스프링 시큐리티에서 기본 사용하고 있는 userDetailService
    @Autowired
    UserDetailsService userDetailsService;

    // 사용자를 생성하기 위한 설정파일
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 임시로 메모리에 사용자를 생성
        auth.inMemoryAuthentication()
                .withUser("user")
                // 패스워드 암호화 알고리즘을 사용하지 않은 비밀번호라는 뜻
                .password("{noop}1234")
                .roles("USER");

        auth.inMemoryAuthentication().withUser("sys").password("{noop}1234").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1234").roles("ADMIN");
    }

    // 인증 & 인가 & 세션에 대한 정책을 설정할 때 사용하는 설정 파일
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책
        http
                // 요청에 대한 보안 검사 기능을 시작
                .authorizeRequests()
                // .antMatchers("/login").permitAll()
                .antMatchers("/test").permitAll()
                .antMatchers("/user/update").hasRole("USER")
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                // 어떤 요청에도 인증을 요구
                .anyRequest().authenticated();

        // 인증 정책
        http
                .formLogin()
                // 사용자 정의 로그인 페이지 => 이 컨트롤러의 이동이 있는지 확인하기
                // .loginPage("/loginPage")
                // 로그인 성공했을 떄
                .defaultSuccessUrl("/")
                // 실패했을 때
                .failureUrl("/login")
                // 사용자 id
                .usernameParameter("userId")
                // password
                .passwordParameter("passwd")
                // 로그인 Form action url => 이는 security 에서 기본 설정으로 /login_proc mapping을 가지고 있게 하고, 이 url을 통해서 인증 요청을 처리하고 있다.
                .loginProcessingUrl("/login_proc")
                // 위 url에서 인증에 성공했을 때 호출, AuthenticationSuccessHandler interface 를 구현한 핸들러를 등록
                // 인증 예외가 발생했다면 발생했던 요청 정보를 캐시로 가지고 있는데 이 정보가 있으면
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    RequestCache requestCache = new HttpSessionRequestCache();
                    SavedRequest savedRequest = requestCache.getRequest(httpServletRequest, httpServletResponse);
                    httpServletResponse.sendRedirect(savedRequest.getRedirectUrl());
                })
                // 위 url에서 자격 증명에 실패 했을 때 호출
                /*.failureHandler((httpServletRequest, httpServletResponse, e) -> {
                    System.out.println("exception : " + e.getMessage());
                    httpServletResponse.sendRedirect("/login");
                })*/
                // 인증을 위한 자원에 대해서는 모든 요청을 허용한다.
                .permitAll()
        ;

        // 로그아웃
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                // LogoutHandler interface를 구현하여야 한다.
                .addLogoutHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    HttpSession session = httpServletRequest.getSession();
                    session.invalidate();
                })
                // LogoutSuccessHandler interface 구현체
                .logoutSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    httpServletResponse.sendRedirect("/login");
                })
                .deleteCookies("remember-me")
        ;

        // remember me 기능
        http
                .rememberMe()
                // 이 파라미터 값이 true로 넘어오면 사용자를 remember 합니다.
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService)
        ;

        // 동시 세션 제어
        http
                .sessionManagement()
                // 동시 세션 1개 허용
                .maximumSessions(1)
                // false => 이전 세션 만료 전략, true => 로그인 실패 (세션 수가 더 늘어나는 것을 막음)
                .maxSessionsPreventsLogin(false)
        ;

        // 세션 고정 보호
        http
                .sessionManagement()
                // 인증 시 세션 아이디 변경
                .sessionFixation().changeSessionId();


        // 인가 예외 처리
        http
                .exceptionHandling()
                // 인증 예외시 처리할 (일종의) 핸들러
                // AuthenticationEntryPoint 를 구현한 구현체
                // 스프링 시큐리티 기본 자원을 사용하기 위해서 주석 처리
                /*.authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> {
                    httpServletResponse.sendRedirect("/login");
                })*/
                // 인가 예외시 처리할 핸들러
                // AccessDeniedHandler 를 구현한 구현체
                .accessDeniedHandler((httpServletRequest, httpServletResponse, e) -> {
                    httpServletResponse.sendRedirect("/denied");
                });

        http.csrf().disable();

    }
}

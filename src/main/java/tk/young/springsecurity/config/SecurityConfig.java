package tk.young.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // Authentication
        http
                .formLogin()
//                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler((request, response, authentication) -> {
                    System.out.println("authentication.getName() = " + authentication.getName());
                    response.sendRedirect("/");
                })
//                .failureHandler((request, response, exception) -> {
//                    System.out.println("exception.getMessage() = " + exception.getMessage());
//                    response.sendRedirect("/");
//                })
                .permitAll();

        // Authorization
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        // Logout
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler((request, response, authentication) -> {
                    HttpSession session = request.getSession();
                    session.invalidate();
                })
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.sendRedirect("/login");
                })
                .deleteCookies("remember-me");

        // Remember me
        http
                .rememberMe()
                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600) // Default 14일
                .alwaysRemember(true) // 리멤버 미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService);

        // Session Management
        // 동시 세션 제어
        http
                .sessionManagement()
                .maximumSessions(1) // 최대 허용 가능 세션 수, -1: 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(false); // 동시 로그인 차단함, false: 기존 세션 만료(default)
//                .invalidSessionUrl("/invalid")
//                .expiredUrl("/expired"); // 세션이 만료된 경우 이동 할 페이지

        // 세션 고정 보호
        http
                .sessionManagement()
                .sessionFixation().changeSessionId(); // 기본값 - 세션 아이디만 변경
//                .sessionFixation().none() // 세션 고정 공격에 취약함
//                .sessionFixation().migrateSession() // 서블릿 버전 3.1 이하 changeSessionId() 와 동일
//                .sessionFixation().newSession() // 이전 세션 프로퍼티값들을 새로 설정해야함

        // 세션 정책
        http
                .sessionManagement()
                .sessionCreationPolicy(
                        SessionCreationPolicy.
                                IF_REQUIRED
//                        ALWAYS
//                        NEVER
//                        STATELESS
                );

/*
        IF_REQUIRED : 필요시 생성(default)
        ALWAYS : 항상 세션 생성
        NEVER : 생성하지 않지만 이미 존재하면 사용
        STATELESS : 생성하지 않고 존재해도 사용하지 않음 (JWT 사용시 해당 설정 사용할것)
*/

    }

}

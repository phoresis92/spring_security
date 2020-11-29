package tk.young.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
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
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@EnableWebSecurity
@RequiredArgsConstructor
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//      스프링 5부터 암호앞에 prefix 로 암호화 방식을 명시해줘야한다. {noop} 평문 저장
        auth.inMemoryAuthentication().withUser("user").password("{noop}123").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}123").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}123").roles("ADMIN", "SYS", "USER");
    }

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
//                .loginProcessingUrl("/login_proc")
                .successHandler((request, response, authentication) -> {
//                    System.out.println("authentication.getName() = " + authentication.getName());
//                    response.sendRedirect("/");

                    HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
                    SavedRequest savedRequest = requestCache.getRequest(request, response);

                    String redirectUrl = savedRequest.getRedirectUrl();
                    response.sendRedirect(redirectUrl);

                })
                .failureHandler((request, response, exception) -> {
                    exception.printStackTrace();
                    System.out.println("exception.getMessage() = " + exception.getMessage());
                    response.sendRedirect("/");
                })
                .permitAll();

        // Authorization
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated();

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
//                .alwaysRemember(true) // 리멤버 미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService);

        // Session Management
        // 동시 세션 제어
        http
                .sessionManagement()
                .maximumSessions(1) // 최대 허용 가능 세션 수, -1: 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true); // 동시 로그인 차단함, false: 기존 세션 만료(default)
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

        // 권한 설정
        // 주의사항 - 설정 시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 해야 한다.
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

//                .antMatcher("/shop/**").authorizeRequests()
//                .antMatchers("/shop/login", "/shop/users/**").permitAll()
//                .antMatchers("/shop/mypage").hasRole("USER")
//                .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
//                .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//                .anyRequest().authenticated();

        /*
            authenticated()                 인증된 사용자의 접근을 허용
            fullyAuthenticated()            인증된 사용자의 접근을 허용, rememberMe 인증 제
            permitAll()                     무조건 접근을 허용
            denyAll()                       무조건 접근을 허용하지 않음
            anonymous()                     익명사용자의 접근을 허용 (Role User는 접근 불)
            rememberMe()                    기억하기를 통해 인증된 사용자의 접근을 허용
            access(String)                  주어진 SpEL 표현식의 평가 결과가 true이면 접근을 허용
            hasRole(String)                 사용자가 주어진 역할이 있다면 접근을 허용가 (Role prefix를 붙이지 않는다)
            hasAuthority(String)            사용자가 주어진 권한이 있다면 (Role prefix를 붙여야 한다)
            hasAnyRole(String...)           사용자가 주어진 권한이 있다면 접근을 허용
            hasAnyAuthority(String...)      사용자가 주어진 권한 중 어떤 것이라도 있다면 접근을 허용
            hasIpAddress(String)            주어진 IP로부터 요청이 왔다면 접근을 허용
        */

        http
                .exceptionHandling()
//                .authenticationEntryPoint((request, response, authException) -> {
//
//                    response.sendRedirect("/login");
//
//                }) // 인증실패 처리
                .accessDeniedHandler((request, response, accessDeniedException) -> {

                    response.sendRedirect("/denied");

                }); // 인가실패 처리

//        http
//                .csrf() // 명시하지 않아도 기본 설정으로 되어있다.
//                .disable();

    }

}

package com.example.springsecurityapplication.config;

import com.example.springsecurityapplication.services.PersonDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig{
    private final PersonDetailsService personDetailsService;

    @Bean // расшифровка пароля - только для тестирования
    public PasswordEncoder getPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        // конфигурируем работу Spring Security
//        http.csrf().disable() // отключаем защиту от межсетевой подделки запросов
        http.authorizeHttpRequests() // казываем что все страницы должны быть защищены аутентификацией
                // указываем что не аутентифицированные пользователи могут зайти на страницу аутнтификации и на объект ошибки с помощью permAll указываем что не аутентифицированные пользователи могут заходить на перечисленные страницы
                .requestMatchers("/admin").hasRole("ADMIN")
                .requestMatchers("/authentication", "/error", "/registration", "/resources/**","/static/**","/css/**", "/product", "/product/info/{id}", "/product/search").permitAll()
                // /css/** - доступ к файлам и папкам для пользователей по ролям
                // указваем что для всех остальных страниц необходимо вызывать метод authenticated(), который открывает форму аутентификации
//                .anyRequest().authenticated()
                // /-admin доступна только пользователю админ

                .anyRequest().hasAnyRole("USER","ADMIN") // остальные страницы доступны всем
                .and() // указываем что дальше настраивается аутентификация и соединяем ее с настройкой доступа
                .formLogin().loginPage("/authentication") // указываем какой url запрос будет отправляться при заходе на защищенные страницы
                .loginProcessingUrl("/process-login") // указываем на какой адрес будут отправляться данные с формы. Нам уже не нужно создавать метод в контроллере и обрабатывать данные с формы. Мы задали url, который используется по умолчанию для обработки формы аутентификации по средствам Spring Security. Spring Security будет создавать объект с формы аутентификации и затем сверять логин и пароль с данными из БД
                .defaultSuccessUrl("/person_account",true) // указываем на какой url необходимо направить пользователя после успешной аутентификации. Вторым аргументом указывается true чтобы перенаправление шло в любом случае после успешной аутентификации
                .failureUrl("/authentication?error") //указываем куда необходимо перенаправить пользователя при проваленной аутентификации. В запросе будет передан объект error, который будет проверяться на форме и при наличии данного объъекта в запросе выводиться сообщение "Неправильный логин или пароль"
                .and()// выход из аккаунта
                .logout().logoutUrl("/logout").logoutSuccessUrl("/authentication");
        return http.build();
    }

    @Autowired
    public SecurityConfig(PersonDetailsService personDetailsService) {
        this.personDetailsService = personDetailsService;
    }

//    private final AuthenticationProvider authenticationProvider;

//    public SecurityConfig(AuthenticationProvider authenticationProvider) {
//        this.authenticationProvider = authenticationProvider;
//    }

    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
//        authenticationManagerBuilder.authenticationProvider(authenticationProvider);
        authenticationManagerBuilder.userDetailsService(personDetailsService)
                .passwordEncoder(getPasswordEncoder());
    }
}

学习SpringSecurity

+ 开始时间：2025-06-20

### 第 1 章 SpringSecurity 基础

创建SpringBoot 项目，且需要引入 SpringBoot、SpringSecurity 依赖，Controller 控制器代码只 Mapping 一个 /hello 的 uri 的方法。

启动项目之后访问 http://localhost:8080/hello ，并不会跳转到此地址，而是会自动跳转到 http://localhost:8080/login，需输入账号密码才能继续访问原地址，账号默认为 user，密码是后端输出的临时密码，点击 Sign in 按钮之后，才会继续访问原 http://localhost:8080/hello 地址。

登录之后，在不关闭浏览器的情况下，再次重新访问 http://localhost:8080/hello ，不会再跳转至登录页面，浏览器会“记住我“，可以直接访问 /hello。

SpringSecurity 是通过基于 Session 机制，采用 Filter（16个 Filter）进行过滤拦截的，SpringBoot 项目里有内嵌的 Tomcat，登录之后，这个 Tomcat 会创建 Session，这个 Session 和前端的 SESSIONID 是绑定的。浏览器的开发者模式中可以找到这个 SESSIONID ，通过这个 SESSIONID，可以找到内嵌的 Tomcat 里的 Session，通过这个就能判断你有没有登录。

SpringSecurity 自动生成 的 /login 页面是通过 框架的 DefaultLoginPageGeneratingFilter （类似这种类有 16 个）这个类自动生成的， 他会根据用户是否登录来选择创建 /login 这个页面

另外，SpringSecurity 框架还提供退出页面，uri 是 /logout，是通过 DefaultLogoutPageGeneratingFilter 这个类自动生成的，点击这个生成页面的 `Log Out`  按钮，立即退出登录并跳转到 http://localhost:8080/login

在 SpringBoot 的配置文件中可以额外配置 SpringSecurity 的自定义账号密码，通过查看框架中的 SecurityProperties 这个类，可以清楚得看到，默认用户名是 user，password 是自动生成的（password = UUID.randomUUID().toString()），可以在我们的 application.yml 中修改配置，类似：

```yaml
spring:
  security:
    user:
      name: sangui
      password: your-password
```

但是，正常是不会通过配置文件来配置账号密码的，而是会选择使用数据库中的数据来登录。

### 第 2 章 通过数据库中的数据来登录 SpringSecurity

选择 MySQL 来实现通过数据库中的信息登录。准备一个 t_user 表，该表中至少有两个字段，login_act，login_pwd，即至少包含账户名，密码。

+ MyBatis 部分

  选择 MyBatis 框架作为 SpringBoot 项目的持久层框架

  + 创建 实体类 TUser 类

  + 创建 Mapper 接口 TUserMapper 类

    注意，该接口中至少要写一个根据用户名（login_act）查找实体类（TUser）的接口方法

  + 创建 mapper 映射文件 TUserMapper.xml 

    注意，至少写一个对应 TUserMapper  接口中的根据用户名查找实体类的 SQL 语句

  + 增加配置信息

    添加数据库，MyBatis 的配置信息，比如：

    ```yaml
    spring:
      datasource:
        username: your-database-username
        password: your-database-password
        driver-class-name: com.mysql.cj.jdbc.Driver
        url: jdbc:mysql://localhost:3306/your-database-name
    mybatis:
      mapper-locations: classpath:/mappers/*.xml
    ```

+ Service 部分

  + 创建 UserService 接口

    注意，该接口必须继承了 UserDetailsService 这个接口。需要在UserService 的实现类中重写 UserDetailsService 接口的 loadUserByUsername 方法。

  + 创建 UserServiceImpl 类

    注意，该类中必须需要重写 UserDetailsService 接口的 loadUserByUsername 方法。这个方法的返回值类型是 UserDetails，这个返回的类是个接口，使用 SpringSecurity 框架的 User 类作为实现类，这个接口中只有三个必要的 getXxx 方法，其他都有默认值先暂时不用管（有四个默认值，是关于账号是否有效的 Boolean 类型的）。这三个方法是：getUsername、getPassword、getAuthorities。所以说，要确定这个方法的返回对象，只需要确定这三个值就可，即 username、password、authorities ，前两个容易理解，是账号密码，第三个是权限，先不管，先暂时设为空。

    所以说，这个 UserServiceImpl  类到底该怎么写？

    这个类只需要重写 loadUserByUsername(String username) 方法即可，该方法中，先通过 tUserMapper 来查询数据库中对应 username 的字段信息整合成 Java 实体类，若找不到，则抛出 SpringSecurity 提供的 UsernameNotFoundException 异常。找到之后，构建 UserDetails 对象返回即可，构建这个对象的实例代码如下：

    ```java
    // 构建一个 SpringSecurity 框架里提供的 UserDetails 对象来返回
    UserDetails userDetails = User.builder()
            .username(tUser.getLoginAct())
            .password(tUser.getLoginPwd())
            // 权限先暂时设为空
            .authorities(AuthorityUtils.NO_AUTHORITIES)
            .build();
    ```
    
    注意，上面代码里的 User 不是我们的实体类，而是 SpringSecurity 框架的 User 类

+ Controller 部分

  创建 uri为 "/hello" 的一个欢迎界面方法即可。

  通过上一章的讲解可以得出，若用户已登录，会访问 http://localhost:8080/hello 的欢迎界面。若用户未登录，会访问 http://localhost:8080/login 的自动登录界面。

至此，看起来整个程序已经完整了，试着运行这个程序，但是发现这个程序还不能运行，后端运行后部分提示如下：

```
Given that there is no default password encoder configured, each password must have a password encoding prefix. Please either prefix this password with '{noop}' or set a default password encoder in `DelegatingPasswordEncoder`.
```

说是缺少了默认的密码加密器，说明此时，应该添加密码加密器程序才能运行。我们通常用的加密器是 SpringSecurity框架自己提供的 BCryptPasswordEncoder 。这时，我们应该额外写一个配置类，即和在 ssm 中的 spring-context.xml 文件中配置 bean 的作用一样的配置类。

+ 配置类部分

  创建一个 SecurityConfig 配置类，将 SpringSecurity 中的 BCrypt 加密器引入我们的 IoC 容器之中该方法中只需要写如下内容。

  ```java
  @Bean
  public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
  }
  ```

  因为 PasswordEncoder 类是 SpringSecurity 框架自己的类，我们不能在框架的类上标注 @Resource 注解来纳入我们自己的 IoC 容器，所以额外写了@Bean 这个注解方法，方法返回这个类的构造方法。 上面代码的内容，相当于 xml 文件中写：（但我们现在是不会选择使用 xml 文件的）

  ```xml
  <bean id="passwordEncoder" class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"/>
  ```

+ 通过数据库中的数据来登录流程总结分析

  1. 访问 http://localhost:8080/hello

  2. 被 SpringSecurity 的 filter 拦截（里面有 16 个 Filter）

  3. 由于我没有登录过，所以 SpringSecurity 就跳转到登录页（登录页是框架生成的）
  
  4. 我们在登录页输入**账号**和**密码**去提交登录（账号密码来自数据库）
  
  5. SpringSecurity里面的 UsernamePasswordAuthenticationFilter 接受账号和密码

  6. 第 5 步的这个 filter 会调用 loadUserByUsername(String username) 方法通过去数据库查询用户
  
  7. 从数据库查询到用户后，把用户组装成 UserDetail 对象，然后返回给 SpringSecurity 框架
  
  8. 第 7 步返回后，会到框架的 AbstractUserDetailsAuthenticationProvider 内部 DefaultXXXAuthenticationChecks 类的 check() 方法进行用户状态的判断，用户对象中默认有 4 个状态 Boolean 字段，如果这 4 个状态字段的值都是 true，该用户才能登录，否则就是提示用户状态不正常，不能登录的）
  
  9. 第7步返回后，再回到框架的 DaoAuthenticationProvider 类的 additionalAuthenticationChecks() 方法进行密码的匹配，如果密码匹配上了，就登录成功，否则失败
  
  10. 比较密码的代码
  
      ```java
      String presentedPassword = authentication.getCredentials().toString();
      if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
          this.logger.debug("Failed to authenticate since password does not match stored value");
          throw new BadCredentialsException(this.messages
              .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
      }
      ```
  
      userDetails 对象是存放密文密码的用户类，authentication 对象是存放明文密码的用户类。上述程序就出现了加密器
  

### 第 3 章 SpringSecurity 使用自定义登录页

这章的程序会在第 2 章程序的基础上进行修改，因为大致程序都相同，只是把登录页从它框架自动生成的，换成是自己的，
# Spring Social Login

In this project we have a [simple spring boot application](src/main/java/com/example/GluuApplication) that implements a very simple Srping web application with OAuth2 SSO. The application home page will show secure content when the user is authenticated and otherwise will show a link for the user to login with Gluu.

## Client code

This simple project uses [AngularJS](https://angularjs.org/) for client side code. You can find the source in [index.html](src/main/resources/static/index.html). In this section we'll break all down for you.

To get started with AngularJS we need to mark the HTML `<body>` as a
Angular app container:

    <body ng-app="app" ng-controller="home as home">
    ...
    </body>

and the `<div>` elements in the body can be bound to a model that
controls which parts of it are displayed:

    <div class="container" ng-show="!home.authenticated">
    	Login with: <a href="/login">Gluu</a>
    </div>
    <div class="container" ng-show="home.authenticated">
    	Logged in as: <span ng-bind="home.user"></span>
    </div>

This HTML sets us up with a need for a "home" controller that has an
`authenticated` flag, and a `user` object describing the authenticated
user. Here's a simple implementation of those features (drop them in
at the end of the `<body>`):

    <script type="text/javascript" src="/webjars/angularjs/angular.min.js"></script>
    <script type="text/javascript">
      angular.module("app", []).controller("home", function($http) {
        var self = this;
        $http.get("/user").success(function(data) {
          self.user = data.userAuthentication.details.name;
          self.authenticated = true;
        }).error(function() {
          self.user = "N/A";
          self.authenticated = false;
        });
      });
    </script>

## Server code

We are using spring boot in this sample to implement the server side. In this section we'll break down the spring boot application.

The main component is the [GluuApplication](src/main/java/com/example/GluuApplication.java) class, which implements the `/user` endpoint that describes the currently
authenticated user:

    @SpringBootApplication
    @EnableOAuth2Sso
    @RestController
    public class GluuApplication {

        @RequestMapping("/user")
        public Principal user(Principal principal) {
            return principal;
        }

        public static void main(String[] args) {
            SpringApplication.run(GluuApplication.class, args);
        }

    }

Note the use of `@RestController` and `@RequestMapping` and the
`java.util.Principal` we inject into the handler method.

WARNING: It's not a great idea to return a whole `Principal` in a
`/user` endpoint like that (it might contain information you would
rather not reveal to a browser client). We only did it to get
something working quickly. Later in the guide we will convert the
endpoint to hide the information we don't need the browser to have.

This app will now work fine and authenticate as before, but without
giving the user a chance to click on the link we just provided. To
make the link visible we also need to switch off the security on the
home page by adding a `WebSecurityConfigurer`:


    @SpringBootApplication
    @EnableOAuth2Sso
    @RestController
    public class GluuApplication extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/**").authorizeRequests()
                    .antMatchers("/", "/login**", "/webjars/**")
                      .permitAll()
                    .anyRequest().authenticated();
        }

        ...
    }


Spring Boot attaches a special meaning to a `WebSecurityConfigurer` on
the class that carries the `@EnableOAuth2Sso` annotation: it uses it
to configure the security filter chain that carries the OAuth2
authentication processor. So all we need to do to make the home page
visible is to explicitly `authorizeRequests()` to the home page and
the static resources it contains (we also include access to the login
endpoints which handle the authentication). All other requests
(e.g. to the `/user` endpoint) require authentication.

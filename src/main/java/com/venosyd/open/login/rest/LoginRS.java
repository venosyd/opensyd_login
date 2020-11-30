package com.venosyd.open.login.rest;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public interface LoginRS {

    String LOGIN_BASE_URI = "/login";

    String LOGIN_ECHO = "/echo";

    String LOGIN_CHECK = "/check";

    String LOGIN_SIGNUP = "/signup";

    String LOGIN_OAUTH_SIGNUP = "/oauth/signup";

    String LOGIN_LOGIN = "/login";

    String LOGIN_OAUTH_LOGIN = "/oauth/login";

    String LOGIN_LOGOUT = "/logout";

    String LOGIN_IS_ENABLED = "/is/enabled";

    String LOGIN_ENABLE = "/enable";

    String LOGIN_DISABLE = "/disable";

    String LOGIN_QUIT_ALL = "/quitall";

    String LOGIN_TOKEN = "/token";

    String LOGIN_UNIQUE = "/unique";

    String LOGIN_ROLE = "/role";

    String LOGIN_ROLES = "/roles";

    String LOGIN_ROLE_GIVE = "/role/give";

    String LOGIN_ROLE_REMOVE = "/role/remove";

    String LOGIN_USERS_BY_ROLE = "/usersbyrole";

    String LOGIN_REQUIRE_PASSW_CHANGE = "/requirechange";

    String LOGIN_PASSW_CHANGE = "/change";

    String LOGIN_PASSW_RESET = "/reset";

    String LOGIN_CHANGE_OLD = "/change/old";

    /**
     * Hello from the server siiiiiiide!
     */
    @GET
    @Path(LOGIN_ECHO)
    @Produces({ MediaType.APPLICATION_JSON })
    Response echo();

    /**
     * check if there is a account with this email
     * 
     * { email: 'fulano@email.com' <or> phone: '99399-3323' database: }
     */
    @POST
    @Path(LOGIN_CHECK)
    @Produces({ MediaType.APPLICATION_JSON })
    Response check(String body);

    /**
     * recebe um email e verifica se eh para logar ou criar uma nova conta
     * 
     * { email: 'fulano@email.com' <optional> phone: '99399-3323' passwd:
     * ABC3838DE9F73ABC28 database: }
     */
    @POST
    @Path(LOGIN_SIGNUP)
    @Produces({ MediaType.APPLICATION_JSON })
    Response signup(String body);

    /**
     * recebe um email e verifica se eh para logar ou criar uma nova conta
     * 
     * { email: 'fulano@email.com' token: ABC3838DE9F73ABC28 database: }
     */
    @POST
    @Path(LOGIN_OAUTH_SIGNUP)
    @Produces({ MediaType.APPLICATION_JSON })
    Response oauthSignup(String body);

    /**
     * loga o usuario no sistema
     * 
     * { email: 'fulano@email.com' <or> phone: '99399-3323' passwd:
     * ABC3838DE9F73ABC28 database: }
     */
    @POST
    @Path(LOGIN_LOGIN)
    @Produces({ MediaType.APPLICATION_JSON })
    Response login(String body);

    /**
     * loga o usuario no sistema
     * 
     * { email: 'fulano@email.com' passwd: ABC3838DE9F73ABC28 database: }
     */
    @POST
    @Path(LOGIN_OAUTH_LOGIN)
    @Produces({ MediaType.APPLICATION_JSON })
    Response oauthLogin(String body);

    /**
     * desloga o usuario do sistema
     * 
     * { token: ABC3838DE9F73ABC28 database: }
     */
    @POST
    @Path(LOGIN_LOGOUT)
    @Produces({ MediaType.APPLICATION_JSON })
    Response logout(String body);

    /**
     * habilita
     * 
     * { credential: database: }
     */
    @POST
    @Path(LOGIN_IS_ENABLED)
    @Produces({ MediaType.APPLICATION_JSON })
    Response isEnabled(String body);

    /**
     * habilita
     * 
     * { credential: database: }
     */
    @POST
    @Path(LOGIN_ENABLE)
    @Produces({ MediaType.APPLICATION_JSON })
    Response enable(String body);

    /**
     * desabilita
     * 
     * { credential: database: }
     */
    @POST
    @Path(LOGIN_DISABLE)
    @Produces({ MediaType.APPLICATION_JSON })
    Response disable(String body);

    /**
     * desabilita
     * 
     * { token: credential: database: }
     */
    @POST
    @Path(LOGIN_UNIQUE)
    @Produces({ MediaType.APPLICATION_JSON })
    Response uniqueID(String body);

    /**
     * desloga de todas as sessoes
     * 
     * { email: 'fulano@email.com' <or> phone: '99399-3323' database: }
     */
    @POST
    @Path(LOGIN_QUIT_ALL)
    @Produces({ MediaType.APPLICATION_JSON })
    Response quitall(String body);

    /**
     * requisita mudanca de senha, link sera enviado para o email, se existir
     * 
     * { email: 'fulano@email.com' database: }
     */
    @POST
    @Path(LOGIN_REQUIRE_PASSW_CHANGE)
    @Produces({ MediaType.APPLICATION_JSON })
    Response requirechange(String body);

    /**
     * muda a senha de um perfil que requisitou a troca de senha
     * 
     * { hash: ABC3838DE9F73ABC28 newpasswd: ABC3838DE9F73ABC28 database: }
     */
    @POST
    @Path(LOGIN_PASSW_CHANGE)
    @Produces({ MediaType.APPLICATION_JSON })
    Response change(String body);

    /**
     * muda a senha de um perfil que requisitou a troca de senha
     * 
     * { credential: user phone or email database: }
     */
    @POST
    @Path(LOGIN_PASSW_RESET)
    @Produces({ MediaType.APPLICATION_JSON })
    Response reset(String body);

    /**
     * muda a senha de um perfil que requisitou a troca de senha
     * 
     * { credential: email or phone oldpasswd: DEF3838DE9F73ABC13 newpasswd:
     * ABC3838DE9F73ABC28 database: }
     */
    @POST
    @Path(LOGIN_CHANGE_OLD)
    @Produces({ MediaType.APPLICATION_JSON })
    Response changeOldPasswd(String body);

    /**
     * when a service receives a token from recent login in its clients, it can
     * check via this function if is valid that profile to login. returns the email
     * which is referred to the user
     * 
     * { token: ABC3838DE9F73ABC28 database: }
     */
    @POST
    @Path(LOGIN_TOKEN)
    @Produces({ MediaType.APPLICATION_JSON })
    Response token(String body);

    /**
     * verifica se o usuario tem a permissao perguntada
     * 
     * { credential: email or phone role: 'godpower' database: }
     */
    @POST
    @Path(LOGIN_ROLE)
    @Produces({ MediaType.APPLICATION_JSON })
    Response role(String body);

    /**
     * lista permissoes do usuario
     * 
     * { credential: email or phone database: }
     */
    @POST
    @Path(LOGIN_ROLES)
    @Produces({ MediaType.APPLICATION_JSON })
    Response roles(String body);

    /**
     * retorna os usuarios com a permissao
     * 
     * { role: 'godpower' database: }
     */
    @POST
    @Path(LOGIN_USERS_BY_ROLE)
    @Produces({ MediaType.APPLICATION_JSON })
    Response listUsersByRole(String body);

    /**
     * verifica se o usuario tem a permissao perguntada
     * 
     * { credential: email or phone role: 'godpower' database: }
     */
    @POST
    @Path(LOGIN_ROLE_GIVE)
    @Produces({ MediaType.APPLICATION_JSON })
    Response giveRole(String body);

    /**
     * verifica se o usuario tem a permissao perguntada
     * 
     * { credential: email or phone role: 'godpower' database: }
     */
    @POST
    @Path(LOGIN_ROLE_REMOVE)
    @Produces({ MediaType.APPLICATION_JSON })
    Response removeRole(String body);

}

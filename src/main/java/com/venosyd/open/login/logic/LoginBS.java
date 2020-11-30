package com.venosyd.open.login.logic;

import java.util.Map;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public interface LoginBS {

    /**
     * singleton
     */
    LoginBS INSTANCE = new LoginBSImpl();

    /**
     * /check if there is a account with this email
     * 
     * { email: 'fulano@email.com' <or> phone: '99399-3323' database: }
     */
    Map<String, String> check(String credential, String database);

    /**
     * /signup recebe um email e verifica se eh para logar ou criar uma nova conta
     * 
     * { email: 'fulano@email.com' <optional> phone: '99399-3323' passwd:
     * ABC3838DE9F73ABC28 database: }
     */
    Map<String, String> signup(String email, String phone, String passwd, String database);

    /**
     * /signup recebe um email e verifica se eh para logar ou criar uma nova conta
     * 
     * { email: 'fulano@email.com' <optional> phone: '99399-3323' passwd:
     * ABC3838DE9F73ABC28 database: }
     */
    Map<String, String> oauthSignup(String email, String token, String database);

    /**
     * /login loga o usuario no sistema
     * 
     * { email: 'fulano@email.com' token: ABC3838DE9F73ABC28 database: }
     */
    Map<String, String> oauthLogin(String credential, String token, String database);

    /**
     * /login loga o usuario no sistema
     * 
     * { email: 'fulano@email.com' <or> phone: '99399-3323' passwd:
     * ABC3838DE9F73ABC28 database: }
     */
    Map<String, String> login(String credential, String passwd, String database);

    /**
     * /logout desloga o usuario do sistema
     * 
     * { token: ABC3838DE9F73ABC28 database: } /
     */
    Map<String, String> logout(String token, String database);

    /**
     * /disable desabilita o login
     * 
     * { credential: database: } /
     */
    Map<String, String> isEnabled(String credential, String database);

    /**
     * /disable desabilita o login
     * 
     * { credential: database: } /
     */
    Map<String, String> disable(String credential, String database);

    /**
     * /enable habilita
     * 
     * { credential: database: } /
     */
    Map<String, String> enable(String credential, String database);

    /**
     * /enable habilita
     * 
     * { credential: database: } /
     */
    Map<String, String> uniqueID(String credential, String database);

}

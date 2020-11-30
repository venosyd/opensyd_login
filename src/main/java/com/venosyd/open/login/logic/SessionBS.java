package com.venosyd.open.login.logic;

import java.util.Map;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public interface SessionBS {

    /**
     * singleton
     */
    SessionBS INSTANCE = new SessionBSImpl();

    /**
     * /quitall desloga de todas as sessoes
     * 
     * { email: 'fulano@email.com' <or> phone: '99399-3323' }
     */
    Map<String, String> quitAllSessions(String credencial, String database);

    /**
     * /token when a service receives a token from recent login in its clients, it
     * can check via this function if is valid that profile to login. returns the
     * email which is referred to the user
     * 
     * { token: ABC3838DE9F73ABC28 }
     */
    Map<String, String> verifyToken(String token, String database);

}

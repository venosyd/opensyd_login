package com.venosyd.open.login.logic;

import java.util.Map;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public interface PasswdBS {

    /**
     * singleton
     */
    PasswdBS INSTANCE = new PasswdBSImpl();

    /**
     * /requirechange requisita mudanca de senha, link sera enviado para o email, se
     * existir
     * 
     * { email: 'fulano@email.com' }
     */
    Map<String, String> requirePasswordChange(String service, String email, String database);

    /**
     * /change muda a senha de um perfil que requisitou a troca de senha
     * 
     * { hash: ABC3838DE9F73ABC28 newpasswd: ABC3838DE9F73ABC28 }
     */
    Map<String, String> changePassword(String hash, String newpasswd, String database);

    /**
     * /reset reseta a senha pra 123456
     * 
     * { credential: ABC3838DE9F73ABC28 }
     */
    Map<String, String> resetPassword(String credential, String database);

    /**
     * /change muda a senha de um perfil que requisitou a troca de senha
     * 
     * { credential: email or phone oldpasswd: DEF3838DE9F73ABC13 newpasswd:
     * ABC3838DE9F73ABC28 }
     */
    Map<String, String> changeOldPassword(String credential, String oldpasswd, String newpasswd, String database);

}

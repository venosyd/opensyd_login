package com.venosyd.open.login.lib;

import com.venosyd.open.commons.util.ReadAssetsFile;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public class LoginChangePasswd extends ReadAssetsFile {

    /** */
    public LoginChangePasswd() {
        super("pages/login_changepasswd.html");
    }

    /**
     * retorna o conteudo do aquivo
     */
    public String getPayload(String service, String hash) {
        var html = super.getContent();
        return html.replace("{{SERVICE}}", service).replace("{{HASH}}", hash);
    }
}
package com.venosyd.open.login.logic;

import java.util.Map;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public interface RoleBS {

    /**
     * singleton
     */
    RoleBS INSTANCE = new RoleBSImpl();

    /**
     * /role checks if a authuser has this power
     * 
     * { credential: email or phone role: 'godpower' }
     */
    Map<String, String> verifyRole(String credential, String role, String database);

    /**
     * /roles checks user roles
     * 
     * { credential: email or phone }
     */
    Map<String, String> verifyRoles(String credential, String database);

    /**
     * /usersbyroles checks if a authuser has this power
     * 
     * { role: 'godpower' }
     */
    Map<String, String> listUsersByRole(String role, String database);

    /**
     * /role checks if a authuser has this power
     * 
     * { credential: email or phone role: 'godpower' }
     */
    Map<String, String> giveRole(String credential, String role, String database);

    /**
     * /role checks if a authuser has this power
     * 
     * { credential: email or phone role: 'godpower' }
     */
    Map<String, String> removeRole(String credential, String role, String database);
}

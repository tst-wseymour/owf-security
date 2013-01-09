package ozone.securitysample.authentication.ldap;

import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.ldap.CommunicationException;
import org.springframework.ldap.PartialResultException;
import org.springframework.ldap.core.LdapOperations;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import ozone.security.authentication.OWFUserDetailsImpl;

public class LdapUserDetailsService
        implements UserDetailsService {

    private static final Log log = LogFactory.getLog(LdapUserDetailsService.class);
    private LdapOperations ldapOperations;
    private String roleSearchBase;
    private String roleSearchQuery;
    private String groupSearchBase;
    private String groupSearchQuery;

    public UserDetails loadUserByUsername(String certificateUserInfo)
            throws UsernameNotFoundException, DataAccessException {
        
        UserDetails userDetails = null;
        try {

            AndFilter andFilterDN = new AndFilter();
            andFilterDN.and(new EqualsFilter("objectClass", "user"));
            andFilterDN.and(new EqualsFilter("sAMAccountName", certificateUserInfo));

            List userDN = ldapOperations.search("", andFilterDN.encode(), new LdapAuthorityGroupContextMapper());
            if (userDN.size() > 0) {
                LdapAuthorityGroup lag = (LdapAuthorityGroup) userDN.get(0);
                String dn = lag.getDn();
                String dn1 = lag.getDn() + lag.getDnBase();
                userDN.clear();


                String preparedRoleSearchQuery = this.roleSearchQuery.replace("?", dn1);
                String preparedGroupSearchQuery = this.groupSearchQuery.replace("?", dn1);
                List userRoles = this.ldapOperations.search("", preparedRoleSearchQuery, new LdapAuthorityGroupContextMapper());
                log.debug("search returned [" + (userRoles != null ? userRoles.size() : 0) + "] role(s)");

                List userGroups = this.ldapOperations.search("", preparedGroupSearchQuery, new LdapAuthorityGroupContextMapper());
                log.debug("search returned [" + (userGroups != null ? userGroups.size() : 0) + "] group(s)");

                userDetails = (UserDetails) this.ldapOperations.lookup(dn, new LdapUserDetailsContextMapper(userRoles, userGroups));
            }
            if (userDetails == null) {
                log.error("No results found for [" + certificateUserInfo + "].");
                throw new UsernameNotFoundException("The user details service was passed authenticated credentials for '" + certificateUserInfo + "', but the credentials were not found. Access to the Ozone Widgeting Framework is denied.");
            }

            if (userDetails.getAuthorities().size() == 0) {
                log.error("No authorities found for [" + certificateUserInfo + "].");
                throw new UsernameNotFoundException("The user details service was passed authenticated credentials for '" + certificateUserInfo + "', but found no authorities assigned. Access to the Ozone Widgeting Framework is denied.");
            }
        } catch (CommunicationException cex) {
            log.error("Communication exception.", cex);
            throw new UsernameNotFoundException("Unable to connect to directory service. Access to the Ozone Widgeting Framework is denied.");
        } catch (Exception ex) {
            log.error("Other exception.", ex);
            throw new UsernameNotFoundException("Unable to process data from directory service. Access to the Ozone Widgeting Framework is denied.");
        }

        log.info("successfully logged in user [" + userDetails.getUsername() + "], authorities [" + ((OWFUserDetailsImpl) userDetails).displayAuthorities() + "], groups [" + ((OWFUserDetailsImpl) userDetails).displayOwfGroups() + "]");
        return userDetails;
    }

    public void setLdapOperations(LdapOperations ldapOperations) {
        this.ldapOperations = ldapOperations;
    }

    public void setGroupSearchBase(String groupSearchBase) {
        this.groupSearchBase = groupSearchBase;
    }

    public void setGroupSearchQuery(String groupSearchQuery) {
        this.groupSearchQuery = groupSearchQuery;
    }

    public String getRoleSearchBase() {
        return this.roleSearchBase;
    }

    public void setRoleSearchBase(String roleSearchBase) {
        this.roleSearchBase = roleSearchBase;
    }

    public void setRoleSearchQuery(String roleSearchQuery) {
        this.roleSearchQuery = roleSearchQuery;
    }

    public LdapOperations getLdapOperations() {
        return this.ldapOperations;
    }

    public String getGroupSearchBase() {
        return this.groupSearchBase;
    }
}
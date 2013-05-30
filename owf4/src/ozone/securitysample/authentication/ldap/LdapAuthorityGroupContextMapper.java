package ozone.securitysample.authentication.ldap;

import javax.naming.directory.Attributes;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;

public class LdapAuthorityGroupContextMapper
        implements ContextMapper {

    private static final Log log = LogFactory.getLog(LdapAuthorityGroupContextMapper.class);

    public Object mapFromContext(Object ctx) {
        LdapAuthorityGroup ldapAuthorityGroup = null;

        if ((ctx != null) && ((ctx instanceof DirContextAdapter))) {
            DirContextAdapter context = (DirContextAdapter) ctx;
            log.debug("converting context [" + context + "]");

            ldapAuthorityGroup = new LdapAuthorityGroup();
            String memberOf = context.getStringAttribute("memberOf");
            if(memberOf != null) {
                memberOf = memberOf.substring(memberOf.indexOf(",DC"));
            }
            ldapAuthorityGroup.setDnBase(memberOf);
            
            ldapAuthorityGroup.setDn(context.getDn().toString());
            ldapAuthorityGroup.setCn(context.getStringAttribute("cn"));
            ldapAuthorityGroup.setMembers(context.getStringAttributes("member"));
            ldapAuthorityGroup.setDescription(context.getStringAttribute("description"));
            ldapAuthorityGroup.setBusinessCategory(context.getStringAttribute("businessCategory"));
            ldapAuthorityGroup.setOrganizationName(context.getStringAttribute("o"));
            ldapAuthorityGroup.setSamAccountName(context.getStringAttribute("sAMAccountName"));
            ldapAuthorityGroup.setC(context.getStringAttribute("c"));
            ldapAuthorityGroup.setOu(context.getStringAttribute("ou"));
            log.debug("ldap authority group [" + ldapAuthorityGroup.toString() + "].");
        }

        return ldapAuthorityGroup;
    }
}
package ozone.securitysample.authentication.ldap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import ozone.security.authentication.OWFUserDetailsImpl;
import ozone.security.authorization.model.GrantedAuthorityImpl;
import ozone.security.authorization.model.OwfGroupImpl;
import ozone.security.authorization.target.OwfGroup;

public class LdapUserDetailsContextMapper
  implements ContextMapper
{
  private static final Log log = LogFactory.getLog(LdapUserDetailsContextMapper.class);
  private List<LdapAuthorityGroup> groups;
  private List<LdapAuthorityGroup> roles;

  public LdapUserDetailsContextMapper(List<LdapAuthorityGroup> roles, List<LdapAuthorityGroup> groups)
  {
    this.roles = roles;
    this.groups = groups;
  }

  public Object mapFromContext(Object ctx)
  {
    UserDetails userDetails = null;

    if ((ctx != null) && ((ctx instanceof DirContextAdapter))) {
      DirContextAdapter context = (DirContextAdapter)ctx;
      log.debug("converting context [" + context + "]");

      Collection authorities = determineAuthorities(context.getDn().toString());

      Collection groups = determineOwfGroups(context.getDn().toString());
      String password = null;
      if(context.getObjectAttribute("userpassword") != null)
          password = context.getObjectAttribute("userpassword").toString();
      userDetails = new OWFUserDetailsImpl(context.getStringAttribute("cn"), password, authorities, groups);

      log.debug("user details [" + userDetails.toString() + "].");
    }

    return userDetails;
  }

  protected Collection<GrantedAuthority> determineAuthorities(String dn)
  {
    Collection authorities = new ArrayList();
    for (LdapAuthorityGroup role : this.roles)
    {
      authorities.add(new GrantedAuthorityImpl("ROLE_" + role.getCn().toUpperCase()));
    }

    return authorities;
  }

  protected Collection<OwfGroup> determineOwfGroups(String dn)
  {
    Collection myGroups = new ArrayList();
    for (LdapAuthorityGroup group : this.groups)
    {
      myGroups.add(new OwfGroupImpl(group.getCn(), group.getDescription(), group.getBusinessCategory(), "active".equals(group.getOrganizationName())));
    }

    return myGroups;
  }
}
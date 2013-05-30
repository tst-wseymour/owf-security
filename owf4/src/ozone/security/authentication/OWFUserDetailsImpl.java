package ozone.security.authentication;

import java.util.ArrayList;
import java.util.Collection;
import org.apache.commons.lang.builder.ReflectionToStringBuilder;
import org.springframework.security.core.GrantedAuthority;
import ozone.security.authorization.target.OwfGroup;

public class OWFUserDetailsImpl
  implements OWFUserDetails
{
  private static final long serialVersionUID = 2L;
  private Collection<GrantedAuthority> authorities = null;

  private String password = null;

  private String username = null;

  private String displayName = null;

  private String organization = null;

  private String email = null;

  private Collection<OwfGroup> owfGroups = new ArrayList();

  public OWFUserDetailsImpl(String username, String password, Collection<GrantedAuthority> authorities, Collection<OwfGroup> groups)
  {
    this.authorities = authorities;
    this.password = password;
    this.username = username;
    this.owfGroups = groups;
  }

  public Collection<GrantedAuthority> getAuthorities() {
    return this.authorities;
  }

  public String getPassword()
  {
    return this.password;
  }

  public String getUsername() {
    return this.username;
  }

  public String getDisplayName() {
    return this.displayName;
  }

  public void setDisplayName(String name) {
    this.displayName = name;
  }

  public String getEmail() {
    return this.email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getOrganization() {
    return this.organization;
  }

  public void setOrganization(String organization) {
    this.organization = organization;
  }

  public Collection<OwfGroup> getOwfGroups() {
    return this.owfGroups;
  }

  public void setOwfGroups(Collection<OwfGroup> owfGroups) {
    this.owfGroups = owfGroups;
  }

  public void addOwfGroup(OwfGroup group)
  {
    this.owfGroups.add(group);
  }

  public boolean isAccountNonExpired() {
    return true;
  }

  public boolean isAccountNonLocked() {
    return true;
  }

  public boolean isCredentialsNonExpired() {
    return true;
  }

  public boolean isEnabled() {
    return true;
  }

  public String toString() {
    return new ReflectionToStringBuilder(this).toString();
  }

  public String displayAuthorities()
  {
    StringBuffer sb = new StringBuffer(255);
    for (GrantedAuthority authority : this.authorities) {
      sb.append(sb.length() > 0 ? "," : "");
      sb.append(authority.getAuthority());
    }
    return sb.toString();
  }

  public String displayOwfGroups()
  {
    StringBuffer sb = new StringBuffer(255);
    for (OwfGroup group : this.owfGroups) {
      sb.append(sb.length() > 0 ? "," : "");
      sb.append(group.getOwfGroupName());
    }
    return sb.toString();
  }
}
package ozone.security.authentication;

import java.util.Collection;
import org.springframework.security.core.userdetails.UserDetails;
import ozone.security.authorization.target.OwfGroup;

public abstract interface OWFUserDetails extends UserDetails
{
  public abstract Collection<OwfGroup> getOwfGroups();

  public abstract String getDisplayName();

  public abstract String getOrganization();

  public abstract String getEmail();
}
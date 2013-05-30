package ozone.security.authorization.model;

import java.io.Serializable;
import ozone.security.authorization.target.OwfGroup;

public class OwfGroupImpl
  implements OwfGroup, Serializable
{
  private static final long serialVersionUID = 1L;
  private String owfGroupName = null;
  private String owfGroupDescription = null;
  private String owfGroupEmail = null;
  private boolean active = true;

  public OwfGroupImpl()
  {
  }

  public OwfGroupImpl(String widgetGroupName, String owfGroupDescription, String owfGroupEmail, boolean active)
  {
    this.owfGroupName = widgetGroupName;
    this.owfGroupDescription = owfGroupDescription;
    this.owfGroupEmail = owfGroupEmail;
    this.active = active;
  }

  public void setOwfGroupName(String name)
  {
    this.owfGroupName = name;
  }

  public String getOwfGroupName()
  {
    return this.owfGroupName;
  }

  public String toString()
  {
    return "OwfGroupImpl [owfGroupName=" + this.owfGroupName + "]";
  }

  public String getOwfGroupDescription()
  {
    return this.owfGroupDescription;
  }

  public void setOwfGroupDescription(String owfGroupDescription)
  {
    this.owfGroupDescription = owfGroupDescription;
  }

  public String getOwfGroupEmail()
  {
    return this.owfGroupEmail;
  }

  public void setOwfGroupEmail(String owfGroupEmail)
  {
    this.owfGroupEmail = owfGroupEmail;
  }

  public boolean isActive()
  {
    return this.active;
  }

  public void setActive(boolean active)
  {
    this.active = active;
  }
}
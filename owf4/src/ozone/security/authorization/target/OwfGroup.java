package ozone.security.authorization.target;

public abstract interface OwfGroup
{
  public abstract String getOwfGroupName();

  public abstract String getOwfGroupDescription();

  public abstract String getOwfGroupEmail();

  public abstract boolean isActive();
}
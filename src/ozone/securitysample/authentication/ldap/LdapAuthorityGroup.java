package ozone.securitysample.authentication.ldap;

import org.apache.commons.lang.builder.ReflectionToStringBuilder;

public class LdapAuthorityGroup
{
  private String dnBase;
  String dn;
  String cn;
  String[] members = new String[0];
  String description;
  String businessCategory;
  String organizationName;
  String sAMAccountName;
  private String c;
  private String ou;
  
  public String getDn()
  {
    return this.dn;
  }

  public void setDn(String dn) {
    this.dn = dn;
  }

  public String getCn() {
    return this.cn;
  }

  public void setCn(String cn) {
    this.cn = cn;
  }

  public String[] getMembers() {
    return this.members;
  }

  public void setMembers(String[] members) {
    this.members = members;
  }

  public String toString() {
    return new ReflectionToStringBuilder(this).toString();
  }

  public String getDescription() {
    return this.description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public String getBusinessCategory() {
    return this.businessCategory;
  }

  public void setBusinessCategory(String businessCategory) {
    this.businessCategory = businessCategory;
  }

  public String getOrganizationName() {
    return this.organizationName;
  }

  public void setOrganizationName(String organizationName) {
    this.organizationName = organizationName;
  }
  
  public String getSamAccountName() {
    return this.sAMAccountName;
  }

  public void setSamAccountName(String sAMAccountName) {
    this.sAMAccountName = sAMAccountName;
  }

    /**
     * @return the c
     */
    public String getC() {
        return c;
    }

    /**
     * @param c the c to set
     */
    public void setC(String c) {
        this.c = c;
    }

    /**
     * @return the ou
     */
    public String getOu() {
        return ou;
    }

    /**
     * @param ou the ou to set
     */
    public void setOu(String ou) {
        this.ou = ou;
    }

    /**
     * @return the dnBase
     */
    public String getDnBase() {
        return dnBase;
    }

    /**
     * @param dnBase the dnBase to set
     */
    public void setDnBase(String dnBase) {
        this.dnBase = dnBase;
    }

}
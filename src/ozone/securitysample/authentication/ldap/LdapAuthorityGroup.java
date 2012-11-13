package ozone.securitysample.authentication.ldap;

import org.apache.commons.lang.builder.ReflectionToStringBuilder;

public class LdapAuthorityGroup
{
  String dn;
  String cn;
  String[] members = new String[0];
  String description;
  String businessCategory;
  String organizationName;
  String sAMAccountName;

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

}
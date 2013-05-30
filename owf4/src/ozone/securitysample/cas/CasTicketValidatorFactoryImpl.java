package ozone.securitysample.cas;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;

public class CasTicketValidatorFactoryImpl
{
  private String casServiceUrl = "";
  private ProxyGrantingTicketStorage proxyGrantingTicketStorage = null;
  private String proxyCallbackUrl = "";

  public Cas20ServiceTicketValidator instantiateValidator()
  {
    Cas20ServiceTicketValidator toReturn = new Cas20ServiceTicketValidator(this.casServiceUrl);
    toReturn.setProxyGrantingTicketStorage(this.proxyGrantingTicketStorage);
    toReturn.setProxyCallbackUrl(this.proxyCallbackUrl);
    return toReturn;
  }

  public String getCasServiceUrl()
  {
    return this.casServiceUrl;
  }

  public void setCasServiceUrl(String casServiceUrl)
  {
    this.casServiceUrl = casServiceUrl;
  }

  public ProxyGrantingTicketStorage getProxyGrantingTicketStorage()
  {
    return this.proxyGrantingTicketStorage;
  }

  public void setProxyGrantingTicketStorage(ProxyGrantingTicketStorage proxyGrantingTicketStorage)
  {
    this.proxyGrantingTicketStorage = proxyGrantingTicketStorage;
  }

  public String getProxyCallbackUrl()
  {
    return this.proxyCallbackUrl;
  }

  public void setProxyCallbackUrl(String proxyCallbackUrl)
  {
    this.proxyCallbackUrl = proxyCallbackUrl;
  }
}
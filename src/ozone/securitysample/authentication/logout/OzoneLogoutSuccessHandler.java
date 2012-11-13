package ozone.securitysample.authentication.logout;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import ozone.securitysample.authentication.audit.AuthenticationUtils;

public class OzoneLogoutSuccessHandler
  implements LogoutSuccessHandler
{
  private String caslogoutSuccessUrl;
  private String defaultLogoutSuccessUrl;
  private static final AuthenticationUtils MP_AUTH_UTILS = new AuthenticationUtils();

  public OzoneLogoutSuccessHandler(String defaultLogoutSuccessUrl, String caslogoutSuccessUrl)
  {
    if (StringUtils.hasText(caslogoutSuccessUrl)) {
      Assert.isTrue(UrlUtils.isValidRedirectUrl(caslogoutSuccessUrl), caslogoutSuccessUrl + " isn't a valid redirect URL");
    }
    Assert.isTrue((!StringUtils.hasLength(defaultLogoutSuccessUrl)) || (UrlUtils.isValidRedirectUrl(defaultLogoutSuccessUrl)), defaultLogoutSuccessUrl + " isn't a valid redirect URL");

    this.caslogoutSuccessUrl = caslogoutSuccessUrl;
    this.defaultLogoutSuccessUrl = defaultLogoutSuccessUrl;
  }

  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
    throws IOException, ServletException
  {
    Cookie sessionCookie = MP_AUTH_UTILS.getRequestCookieByName(request, "JSESSIONID");
    if (sessionCookie != null) {
      sessionCookie.setPath(request.getContextPath());
      sessionCookie.setMaxAge(0);
      response.addCookie(sessionCookie);
    }

    getUrlLogoutSuccessHandlerByAuthentication(authentication).onLogoutSuccess(request, response, authentication);
  }

  private SimpleUrlLogoutSuccessHandler getUrlLogoutSuccessHandlerByAuthentication(Authentication authentication)
  {
    SimpleUrlLogoutSuccessHandler urlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
    if ((authentication instanceof CasAuthenticationToken)) {
      if (StringUtils.hasText(this.caslogoutSuccessUrl)) {
        urlLogoutSuccessHandler.setDefaultTargetUrl(this.caslogoutSuccessUrl);
      }
    }
    else if (StringUtils.hasText(this.defaultLogoutSuccessUrl)) {
      urlLogoutSuccessHandler.setDefaultTargetUrl(this.defaultLogoutSuccessUrl);
    }

    return urlLogoutSuccessHandler;
  }
}
package ozone.securitysample.authentication.logout;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

public class OzoneLogoutFilter extends LogoutFilter
{
  public OzoneLogoutFilter(String logoutUrl, LogoutSuccessHandler logoutSuccessHandler, LogoutHandler[] handlers)
  {
    super(logoutSuccessHandler, handlers);

    setFilterProcessesUrl(logoutUrl);
  }

  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException
  {
    HttpServletRequest request = (HttpServletRequest)req;
    HttpServletResponse response = (HttpServletResponse)res;

    if (requiresLogout(request, response)) {
      addAuthenticationToServletRequest(req, res);
    }

    super.doFilter(req, res, chain);
  }

  protected void addAuthenticationToServletRequest(ServletRequest req, ServletResponse res) {
    SecurityContext context = SecurityContextHolder.getContext();
    if (context != null) {
      Authentication authentication = context.getAuthentication();
      if (authentication != null)
      {
        req.setAttribute("MP_SPRING_SECURITY_AUTHENTICATION", authentication);
      }
    }
  }
}
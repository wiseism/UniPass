package com.unipass.server;

import jakarta.servlet.http.*;
import org.springframework.core.io.*;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@Controller
public final class PortalPages {
    private final PortalContinuations continuations;
    public PortalPages(PortalContinuations continuations){this.continuations=continuations;}
    @GetMapping("/") String root(){return "redirect:/portal/";}
    @GetMapping(value={"/login","/reset","/portal/","/portal/mfa","/portal/password","/portal/factors","/portal/sessions","/portal/binding","/portal/admin"},produces=MediaType.TEXT_HTML_VALUE)
    ResponseEntity<Resource> page(){
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("Referrer-Policy","same-origin").body(new ClassPathResource("META-INF/resources/portal/index.html"));
    }
    @PostMapping("/portal/continue") void resume(@AuthenticationPrincipal IdentityPrincipal principal,@RequestParam UUID id,HttpServletRequest request,HttpServletResponse response)throws java.io.IOException{
        try {response.sendRedirect(continuations.resume(request,principal,id));}
        catch(org.springframework.web.server.ResponseStatusException failure){
            if(!PortalContinuations.html(request))throw failure;
            response.sendRedirect("/portal/?flow_error");
        }
    }
}

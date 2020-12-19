vcl 4.0;
import directors;
import std;

# Features:
# - this VCL is for using cache tags with drupal 8. Minor chages of VCL provided by Jeff Geerling.

acl upstream_proxy_acl {
    "app";
    "127.0.0.1";
}


# Backend definition. Set this to point to your content server.
backend app {
    .host = "app";
    .port = "80";
    .connect_timeout = 300s;
    .between_bytes_timeout = 300s;
    .first_byte_timeout = 300s;
    .probe = {
        .url = "/";
        .timeout = 1s;
        .interval = 5s;
        .window = 5;
        .threshold = 3;
    }
}


acl purge_acl {
    # App server(s)
    "app";
    # EdW
    "5.2.158.243";
    # Jenkins - Steward
    "159.69.95.10";
}


sub vcl_init {
    new bar = directors.fallback();
    bar.add_backend(app);

    # Alternative config for load-balancing
    # new bar = directors.round_robin();
    # bar.add_backend(d1);
    # bar.add_backend(d2);
    # bar.add_backend(d3);
}


sub vcl_recv {
    # Happens before we check if we have this in cache already.
    # Typically you clean up the request here, removing cookies you don't need,
    # rewriting the request, etc.
    set req.backend_hint = bar.backend();

    # Set the X-Forwarded-For header so the backend can see the original
    # IP address. If one is already set by an upstream proxy, we'll just re-use that.
    if (client.ip ~ upstream_proxy_acl && req.http.X-Forwarded-For) {
        set req.http.X-Forwarded-For = req.http.X-Forwarded-For;
    } else {
        set req.http.X-Forwarded-For = regsub(client.ip, ":.*", "");
    }

    # std.syslog(0, "" + req.http.X-Real-IP);
    # std.syslog(0, req.http.X-Forwarded-For);

    # Handle PURGE requests
    if (req.method == "PURGE") {
        # Check the IP is allowed.
        if (!client.ip ~ purge_acl) {
            return (synth(403, "Not allowed."));
        }
        return (purge);
    }

    # Handle BAN requests
    if (req.method == "BAN") {
        if (!client.ip ~ purge_acl) {
            return (synth(403, "Not allowed."));
        }
        # Logic for the ban, using the Cache-Tags header. For more info
        # see https://github.com/geerlingguy/drupal-vm/issues/397.
        if (req.http.Cache-Tags) {
            ban("obj.http.Cache-Tags ~ " + req.http.Cache-Tags);
        }
        else {
            return (synth(403, "Cache-Tags header missing."));
        }
        return (synth(200, "Ban added."));
    }

    # Clear entire domain
    if (req.method == "FULLBAN") {
         if (!client.ip ~ purge_acl) {
            return (synth(403, "Not allowed."));
        }
        ban("req.http.host ~ .*");
        return (synth(200, "Full cache cleared"));
    }

    # Auth
    if (req.method == "URIBAN") {
        if (!client.ip ~ purge_acl) {
            return (synth(403, "Not allowed."));
        }
        ban("req.http.host == " + req.http.host + " && req.url == " + req.url);
        # Throw a synthetic page so the request won't go to the backend
        return (synth(200, "Ban added."));
    }

    # Only cache GET and HEAD requests (pass through POST requests).
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Do not cache these paths.
    if (req.url ~ "^/status\.php$" ||
        req.url ~ "^/update\.php" ||
        req.url ~ "^/install\.php" ||
        req.url ~ "^/apc\.php$" ||
        req.url ~ "^/admin$" ||
        req.url ~ "^/admin/.*$" ||
        req.url ~ "^/user" ||
        req.url ~ "^/user/.*$" ||
        req.url ~ "^/users/.*$" ||
        req.url ~ "^/info/.*$" ||
        req.url ~ "^/flag/.*$" ||
        req.url ~ "^.*/ajax/.*$" ||
        req.url ~ "^.*/ahah/.*$" ||
        req.url ~ "^/manage/.*$" ||
        req.url ~ "^/system/files/.*$") {
            return (pass);
    }

    # Do not cache any PDF/archive files
    if (req.url ~ "(?i)\/pdf(\?.*)?$" ||
        req.url ~ "(?i)\.(pdf|zip|gz|tgz)(\?.*)?$") {
	    return (pass);
    }

    # Always cache the following file types for all users. This list of extensions
    # appears twice, once here and again in vcl_backend_response so make sure you edit both
    # and keep them equal.
    if (req.url ~ "(?i)\.(asc|dat|txt|csv|png|gif|jpeg|jpg|ico|svg|swf|css|js)(\?.*)?$") {
        unset req.http.Cookie;
    }

    # Remove all cookies that Drupal doesn't need to know about. We explicitly
    # list the ones that Drupal does need, the SESS and NO_CACHE. If, after
    # running this code we find that either of these two cookies remains, we
    # will pass as the page cannot be cached.
    if (req.http.Cookie) {
        # Backup cookies to use in vcl_hash (Cookie-based language negotiation)
        set req.http.Cookies-Backup = req.http.Cookie;

        # 1. Append a semi-colon to the front of the cookie string.
        # 2. Remove all spaces that appear after semi-colons.
        # 3. Match the cookies we want to keep, adding the space we removed
        #    previously back. (\1) is first matching group in the regsuball.
        # 4. Remove all other cookies, identifying them by the fact that they have
        #    no space after the preceding semi-colon.
        # 5. Remove all spaces and semi-colons from the beginning and end of the
        #    cookie string.
        set req.http.Cookie = ";" + req.http.Cookie;
        set req.http.Cookie = regsuball(req.http.Cookie, "; +", ";");
        set req.http.Cookie = regsuball(req.http.Cookie, ";(SESS[a-z0-9]+|SSESS[a-z0-9]+|NO_CACHE)=", "; \1=");
        set req.http.Cookie = regsuball(req.http.Cookie, ";[^ ][^;]*", "");
        set req.http.Cookie = regsuball(req.http.Cookie, "^[; ]+|[; ]+$", "");

        if (req.http.Cookie == "") {
            # If there are no remaining cookies, remove the cookie header. If there
            # aren't any cookie headers, Varnish's default behavior will be to cache
            # the page.
            unset req.http.Cookie;
        }
        else {
            # If there is any cookies left (a session or NO_CACHE cookie), do not
            # cache the page. Pass it on to Apache directly.
            return (pass);
        }
    }
}


sub vcl_hash {
    # URL and hostname/IP are the default components of the vcl_hash
    # implementation. We add more below.
    hash_data(req.url);
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }

    # Cookie-based language negotiation
    if (req.http.Cookies-Backup ~ "x_content_language=ar") {
       set req.http.X-Content-Language = "ar";
       hash_data(req.http.X-Content-Language);
    }
    if (req.http.Cookies-Backup ~ "x_content_language=en") {
       set req.http.X-Content-Language = "en";
       hash_data(req.http.X-Content-Language);
    }
    if (req.http.Cookies-Backup ~ "x_content_language=es") {
       set req.http.X-Content-Language = "es";
       hash_data(req.http.X-Content-Language);
    }
    if (req.http.Cookies-Backup ~ "x_content_language=fr") {
       set req.http.X-Content-Language = "fr";
       hash_data(req.http.X-Content-Language);
    }
    if (req.http.Cookies-Backup ~ "x_content_language=ru") {
       set req.http.X-Content-Language = "ru";
       hash_data(req.http.X-Content-Language);
    }
    if (req.http.Cookies-Backup ~ "x_content_language=zh-hans") {
       set req.http.X-Content-Language = "zh-hans";
       hash_data(req.http.X-Content-Language);
    }
    if (req.http.Cookies-Backup != "") {
       unset req.http.Cookies-Backup;
    }

    # Include the X-Forward-Proto header, since we want to treat HTTPS
    # requests differently, and make sure this header is always passed
    # properly to the backend server.
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }
    return (lookup);
}


# Instruct Varnish what to do in the case of certain backend responses (beresp).
sub vcl_backend_response {
    # Happens after we have read the response headers from the backend.
    #
    # Here you clean the response headers, removing silly Set-Cookie headers
    # and other mistakes your backend does.

    # Set ban-lurker friendly custom headers.
    set beresp.http.X-Url = bereq.url;
    set beresp.http.X-Host = bereq.http.host;

    # Cache 404s, 301s, at 500s with a short lifetime to protect the backend.
    if (beresp.status == 404 || beresp.status == 301 || beresp.status == 500) {
        set beresp.ttl = 10m;
    }

    # Don't allow static files to set cookies.
    # (?i) denotes case insensitive in PCRE (perl compatible regular expressions).
    # This list of extensions appears twice, once here and again in vcl_recv so
    # make sure you edit both and keep them equal.
    if (bereq.url ~ "(?i)\.(asc|dat|txt|csv|png|gif|jpeg|jpg|ico|svg|swf|css|js)(\?.*)?$") {
        unset beresp.http.set-cookie;
    }

    # Allow items to remain in cache up to 6 hours past their cache expiration.
    set beresp.grace = 6h;
}


sub vcl_backend_error {
    set beresp.http.Content-Type = "text/html; charset=utf-8";
    set beresp.http.Retry-After = "5";
    synthetic( {"<!DOCTYPE html>
      <html>
        <head>
          <title>Something's not working properly</title>
        </head>
        <body style="margin-top: 150px">
          <center>
          <h1>Something's not working properly</h1>
          <p>It's our fault, please try again in few minutes.</p>
          <p>"} + beresp.reason + {" ("} + beresp.status + {"), XID:"} + bereq.xid + {"</p>
          </center>
        </body>
      </html>
    "});
    return (deliver);
}


sub vcl_deliver {
    # Remove ban-lurker friendly custom headers when delivering to client.
    unset resp.http.X-Url;
    unset resp.http.X-Host;

    # Happens when we have all the pieces we need, and are about to send the
    # response to the client.
    # You can do accounting or modifying the final object here.
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
}

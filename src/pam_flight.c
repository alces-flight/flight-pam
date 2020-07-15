#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <errno.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#include <curl/curl.h>

/* Expected hooks that are not supported. */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_AUTH_ERR; /* Service not supported */
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_AUTHTOK_ERR; /* Service not supported */
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SESSION_ERR; /* Service not supported */
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SESSION_ERR; /* Service not supported */
}

    const char *
str_skip_icase_prefix(const char *str, const char *prefix)
{
    size_t prefix_len = strlen(prefix);
    return strncasecmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

struct flight_args {
    const char *url;
    int debug;
    int permit_non_mapped_users;
    long minuid;
};

    static int
parse_args(pam_handle_t *pamh, struct flight_args *flightargs,
        int argc, const char **argv)
{
    char *endptr;
    long val;
    flightargs->url = NULL;
    flightargs->debug = 0;
    flightargs->permit_non_mapped_users = 1;
    flightargs->minuid = 1000;

    int i;
    for (i=0; i<argc; ++i) {
        const char *str;
        if (strcasecmp(argv[i], "debug") == 0) {
            flightargs->debug = 1;
            continue;
        }
        str = str_skip_icase_prefix(argv[i], "url=");
        if (str != NULL) {
            flightargs->url = str;
            continue;
        }
        str = str_skip_icase_prefix(argv[i], "permit_non_mapped_users=");
        if (str != NULL) {
            if ((strcmp(str, "1") == 0) || (strcasecmp(str, "true") == 0)) {
                flightargs->permit_non_mapped_users = 1;
            } else {
                flightargs->permit_non_mapped_users = 0;
            }
            continue;
        }
        str = str_skip_icase_prefix(argv[i], "minuid=");
        if (str != NULL) {
            errno = 0;
            val = strtol(str, &endptr, 10);
            if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
                    || (errno != 0 && val == 0)) {
                pam_syslog(pamh, LOG_ERR, "invalid value for minuid=%s", str);
                return 0;
            }
            if (endptr == str) {
                pam_syslog(pamh, LOG_ERR, "invalid value for minuid=%s", str);
                return 0;
            }
            if (val < 1) {
                pam_syslog(pamh, LOG_ERR, "invalid value for minuid=%s", str);
                return 0;
            }
            flightargs->minuid = val;
            continue;
        }
        pam_syslog(pamh, LOG_ERR, "unrecognized option [%s]", argv[i]);
    }
    return 1;
}

void jsonEscapeString(char* dst, const char* src) {
    int srcIdx, dstIdx;
    int len = strlen(src);
    for (srcIdx = 0, dstIdx = 0; srcIdx<len; srcIdx++, dstIdx++) {
        if (src[srcIdx] == '\\' || src[srcIdx] == '"') {
            dst[dstIdx] = '\\';
            dstIdx++;
        }
        dst[dstIdx] = src[srcIdx];
    }
    dst[dstIdx] = '\0';
}

/*
 * Return JSON string containing Flight SSO credentials or NULL.
 *
 * The caller needs to free the returned pointer.
 */
char* buildCredentials(const char* username, const char* password) {
    char* escapedUsername;
    char* escapedPassword;
    char* credentials;
    int credentialsLen;

    escapedUsername = malloc(strlen(username) * 2);
    if (escapedUsername == NULL) {
        return NULL;
    }
    jsonEscapeString(escapedUsername, username);

    escapedPassword = malloc(strlen(password) * 2);
    if (escapedPassword == NULL) {
        free(escapedUsername);
        return NULL;
    }
    jsonEscapeString(escapedPassword, password);

    credentialsLen = strlen(escapedUsername) + strlen(escapedPassword) + 42;
    credentials = malloc(credentialsLen);
    if (credentials == NULL) {
        free(escapedUsername);
        free(escapedPassword);
        return NULL;
    }
    sprintf(credentials, "{\"account\":{\"username\":\"%s\",\"password\":\"%s\"}}",
            escapedUsername, escapedPassword);
    return credentials;
}

/*
 * Function to handle stuff from HTTP response.
 *
 * @param buf- Raw buffer from libcurl.
 * @param len- number of indices
 * @param size- size of each index
 * @param userdata- any extra user data needed
 * @return Number of bytes actually handled. If different from len * size, curl will throw an error
 */
static int writeFn(void* buf, size_t len, size_t size, void* userdata) {
    return len * size;
}


/**
 * HTTP Response returned from a HTTP request.
 */
typedef struct {
    bool error;
    const char* msg;
} HttpError;

typedef struct {
    long responseCode;
    HttpError err;
} HttpResponse;


static int authenticate_user(pam_handle_t *pamh, struct flight_args flightargs, const char* pUsername, const char* pPassword) {
    CURL* pCurl = curl_easy_init();
    int curlResponse = -1;
    int authStatus = PAM_AUTH_ERR;
    char* pCredentials;

    if (!pCurl) {
        pam_syslog(pamh, LOG_CRIT, "error initialising curl");
        return PAM_BUF_ERR;
    }

    HttpResponse* httpResponse = malloc(sizeof(HttpResponse));
    if (httpResponse == NULL) {
        pam_syslog(pamh, LOG_CRIT, "pam_flight: cannot allocate httpResponse");
        curl_easy_cleanup(pCurl);
        return PAM_BUF_ERR;
    }

    pCredentials = buildCredentials(pUsername, pPassword);
    if (pCredentials == NULL) {
        pam_syslog(pamh, LOG_CRIT, "pam_flight: cannot build credentials");
        curl_easy_cleanup(pCurl);
        free(httpResponse);
        return PAM_AUTH_ERR;
    }

    curl_easy_setopt(pCurl, CURLOPT_URL, flightargs.url);
    curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, writeFn);
    curl_easy_setopt(pCurl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, pCredentials);
    curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1); // we don't care about progress
    curl_easy_setopt(pCurl, CURLOPT_FAILONERROR, 0);
    // we don't want to leave our user waiting at the login prompt forever
    curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, 1);
#ifdef DEBUG
    curl_easy_setopt(pCurl, CURLOPT_VERBOSE, 1L);
#endif

    struct curl_slist *pHeaders = NULL;
    pHeaders = curl_slist_append(pHeaders, "Accept: application/json");
    pHeaders = curl_slist_append(pHeaders, "Content-Type: application/json");
    curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, pHeaders);

    // SSL needs 16k of random stuff. We'll give it some space in RAM.
    curl_easy_setopt(pCurl, CURLOPT_RANDOM_FILE, "/dev/urandom");
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2);
    curl_easy_setopt(pCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

    curlResponse = curl_easy_perform(pCurl);
    curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &httpResponse->responseCode);
    HttpError *error = &httpResponse->err;
    error->error = (curlResponse != CURLE_OK);
    error->msg = curl_easy_strerror(curlResponse);

    if (httpResponse->err.error) {
        authStatus = PAM_AUTH_ERR;
        pam_syslog(pamh, LOG_ERR, "authentication error; username=%s url=%s http_response=%s", pUsername, flightargs.url, httpResponse->err.msg);
    } else {
        if (httpResponse->responseCode == 200) {
            authStatus = PAM_SUCCESS;
            pam_syslog(pamh, LOG_NOTICE, "authentication success; username=%s url=%s http_response=%ld", pUsername, flightargs.url, httpResponse->responseCode);

        } else if (httpResponse->responseCode == 401) {
            authStatus = PAM_PERM_DENIED;
            pam_syslog(pamh, LOG_NOTICE, "authentication failure; username=%s url=%s http_response=%ld", pUsername, flightargs.url, httpResponse->responseCode);
        } else {
            authStatus = PAM_AUTH_ERR;
            pam_syslog(pamh, LOG_NOTICE, "authentication error; username=%s url=%s http_response=%ld", pUsername, flightargs.url, httpResponse->responseCode);
        }
    }

    memset(pCredentials, '\0', strlen(pCredentials));
    free(pCredentials);
    curl_easy_cleanup(pCurl);
    curl_slist_free_all(pHeaders);
    free(httpResponse);

    return authStatus;
}

static int get_user_name(pam_handle_t *pamh, const char** userName) {
    int status;
    int retval = pam_get_user(pamh, userName, NULL);
    if (retval != PAM_SUCCESS || userName == NULL || *userName == NULL) {
        status = PAM_AUTHINFO_UNAVAIL;
    } else {
        status = PAM_SUCCESS;
    }
    return status;
}

/* Expected hooks that are supported. */

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char **argv) {
    struct flight_args flightargs;
    int ret = PAM_AUTH_ERR;
    const char* pUnixUsername = NULL;
    const char* pPassword = NULL;
    const void *pUserMap = NULL;
    const char *pFlightUsername = NULL;
    struct passwd *user;

    memset(&flightargs, '\0', sizeof(flightargs));
    if (!parse_args(pamh, &flightargs, argc, argv)) {
        pam_syslog(pamh, LOG_ERR, "failed to parse the module arguments");
        return PAM_ABORT;
    }

    if (!flightargs.url) {
        pam_syslog(pamh, LOG_CRIT, "pam_flight: `url` argument not given");
        return PAM_SERVICE_ERR;
    }

    ret = get_user_name(pamh, &pUnixUsername);
    if (ret != PAM_SUCCESS) {
        if (flightargs.debug) {
            pam_syslog(pamh, LOG_DEBUG, "could not obtain username");
        }
        return ret;
    }

    ret = pam_get_authtok(pamh, PAM_AUTHTOK, &pPassword , "Flight Password: ");
    if (ret != PAM_SUCCESS) {
        if (ret != PAM_CONV_AGAIN) {
            pam_syslog(pamh, LOG_CRIT,
                    "auth could not identify password for [%s]", pUnixUsername);
        } else {
            /*
             * It is safe to resume this function so we translate this
             * retval to the value that indicates we're happy to resume.
             */
            ret = PAM_INCOMPLETE;
        }
        pUnixUsername = NULL;
        return ret;
    }

    ret = pam_get_data(pamh, "pam_flight_user_map_data", &pUserMap);
    if (ret == PAM_SUCCESS && pUserMap) {
        pFlightUsername = (const char *)pUserMap;
        if (flightargs.debug) {
            pam_syslog(pamh, LOG_DEBUG, "username mapped from=%s to=%s", pUnixUsername, pFlightUsername);
        }
    } else if (flightargs.permit_non_mapped_users) {
        pFlightUsername = pUnixUsername;
        if (flightargs.debug) {
            pam_syslog(pamh, LOG_DEBUG, "username not mapped; using username=%s", pFlightUsername);
        }
    } else {
        if (flightargs.debug) {
            pam_syslog(pamh, LOG_DEBUG, "authentication failure; username not mapped");
        }
        return PAM_PERM_DENIED;
    }

    /*
     * We don't want to allow spammed SSH attempts from bots to DDOS the
     * SSO server.  We only continue with an attempt to authenticate if
     * there is a local user matching pUnixUsername.
     *
     * We do this after we've prompted for the password to avoid leaking
     * which users exist.
     *
     * Unfortunately, we're not making an HTTP request and hence returning
     * much earlier.  This leaves us open to a timing attack to determine
     * which local users exist.
     */
    if ((user = pam_modutil_getpwnam(pamh, pUnixUsername)) == NULL) {
        pam_syslog(pamh, LOG_NOTICE, "authentication error; user unknown [%s]", pUnixUsername);
        return PAM_USER_UNKNOWN;
    }
    if (user->pw_uid == 0) {
        if (flightargs.debug) {
            pam_syslog(pamh, LOG_DEBUG, "authentication failure; uid=%d not permitted",
                    user->pw_uid);
        }
        return PAM_PERM_DENIED;
    }
    if (user->pw_uid < flightargs.minuid) {
        if (flightargs.debug) {
            pam_syslog(pamh, LOG_DEBUG, "authentication failure; uid=%d below minuid=%ld",
                    user->pw_uid, flightargs.minuid);
        }
        return PAM_PERM_DENIED;
    }

    ret = authenticate_user(pamh, flightargs, pFlightUsername, pPassword);
    return ret;
}

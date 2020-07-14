#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>

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

int buildCredentials(pam_handle_t *pamh, char *credentials, const char* username, const char* password) {
	char* escapedUsername;
	char* escapedPassword;
	int credentialsLen;

	escapedUsername = malloc(strlen(username) * 2);
	if (escapedUsername == NULL) {
		pam_syslog(pamh, LOG_CRIT,
				"pam_flight: cannot allocate escapedUsername");
		return PAM_BUF_ERR;
	}
	jsonEscapeString(escapedUsername, username);

	escapedPassword = malloc(strlen(password) * 2);
	if (escapedUsername == NULL) {
		pam_syslog(pamh, LOG_CRIT,
				"pam_flight: cannot allocate escapedPassword");
		free(escapedUsername);
		return PAM_BUF_ERR;
	}
	jsonEscapeString(escapedPassword, password);

	credentialsLen = strlen(escapedUsername) + strlen(escapedUsername) + 42;
	credentials = malloc(credentialsLen);
	if (credentials == NULL) {
		pam_syslog(pamh, LOG_CRIT,
				"pam_flight: cannot allocate credentials");
		free(escapedUsername);
		free(escapedPassword);
		return PAM_BUF_ERR;
	}
	sprintf(credentials, "{\"account\":{\"username\":\"%s\",\"password\":\"%s\"}}",
			escapedUsername, escapedUsername);
	return PAM_SUCCESS;
}

/*
 * Makes getting arguments easier. Accepted arguments are of the form: name=value
 *
 * @param pName- name of the argument to get
 * @param argc- number of total arguments
 * @param argv- arguments
 * @return Pointer to value or NULL
 */
static const char* getArg(const char* pName, int argc, const char** argv) {
	int len = strlen(pName);
	int i;

	for (i = 0; i < argc; i++) {
		if (strncmp(pName, argv[i], len) == 0 && argv[i][len] == '=') {
			// only give the part url part (after the equals sign)
			return argv[i] + len + 1;
		}
	}
	return 0;
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


static int authenticate_user(pam_handle_t *pamh, const char* pUrl, const char* pUsername, const char* pPassword) {
	CURL* pCurl = curl_easy_init();
	int curlResponse = -1;
	int authStatus = PAM_AUTH_ERR;
	char* pCredentials = NULL;

	if (!pCurl) {
		pam_syslog(pamh, LOG_ERR, "error initialising curl");
		return PAM_AUTH_ERR;
	}

	HttpResponse* httpResponse = malloc(sizeof(HttpResponse));
	if (httpResponse == NULL) {
		pam_syslog(pamh, LOG_CRIT, "pam_flight: cannot allocate httpResponse");
		curl_easy_cleanup(pCurl);
		return PAM_BUF_ERR;
	}

	if ((authStatus = buildCredentials(pamh, pCredentials, pUsername, pPassword)) != PAM_SUCCESS) {
		if (pCredentials != NULL) {
			free(pCredentials);
		}
		return authStatus;
	}

	curl_easy_setopt(pCurl, CURLOPT_URL, pUrl);
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
		pam_syslog(pamh, LOG_ERR, "authentication error; username=%s url=%s http_response=%s", pUsername, pUrl, httpResponse->err.msg);
	} else {
		if (httpResponse->responseCode == 200) {
			authStatus = PAM_SUCCESS;
			pam_syslog(pamh, LOG_DEBUG, "authentication success; username=%s url=%s http_response=%ld", pUsername, pUrl, httpResponse->responseCode);

		} else if (httpResponse->responseCode == 401) {
			authStatus = PAM_PERM_DENIED;
			pam_syslog(pamh, LOG_DEBUG, "authentication failure; username=%s url=%s http_response=%ld", pUsername, pUrl, httpResponse->responseCode);
		} else {
			authStatus = PAM_AUTH_ERR;
			pam_syslog(pamh, LOG_DEBUG, "authentication error; username=%s url=%s http_response=%ld", pUsername, pUrl, httpResponse->responseCode);
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
		pam_syslog(pamh, LOG_DEBUG, "could not obtain user");
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
	int ret = PAM_AUTH_ERR;
	const char* pUnixUsername = NULL;
	const char* pPassword = NULL;
	const char* pUrl = NULL;
	const void *pUserMap = NULL;
	const char *pFlightUsername = NULL;

	ret = get_user_name(pamh, &pUnixUsername);
	if (ret != PAM_SUCCESS) {
		return ret;
	}

	ret = pam_get_data(pamh, "pam_flight_user_map_data", &pUserMap);
	if (ret == PAM_SUCCESS && pUserMap) {
		pFlightUsername = (const char *)pUserMap;
		pam_syslog(pamh, LOG_DEBUG, "username mapped from=%s to=%s", pUnixUsername, pFlightUsername);
	} else {
		pFlightUsername = pUnixUsername;
		pam_syslog(pamh, LOG_DEBUG, "username mapping data not found");
	}
	
	pUrl = getArg("url", argc, argv);
	if (!pUrl) {
		pam_syslog(pamh, LOG_CRIT, "pam_flight: `url` argument not given");
		return PAM_SERVICE_ERR;
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
	if (pam_modutil_getpwnam(pamh, pUnixUsername) == NULL) {
		pam_syslog(pamh, LOG_DEBUG, "user unknown [%s]", pUnixUsername);
		return PAM_USER_UNKNOWN;
	}

	ret = authenticate_user(pamh, pUrl, pFlightUsername, pPassword);
	return ret;
}

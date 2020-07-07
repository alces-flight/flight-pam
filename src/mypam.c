#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <security/pam_modules.h>
#include <curl/curl.h>

#ifdef DEBUG
#define PAM_DEBUG(fmt...) fprintf(stderr, "DEBUG: " fmt);
#else
#define PAM_DEBUG(fmt...)
#endif

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


static int authenticate_user(const char* pUrl, const char* pUsername, const char* pPassword, const char* pCaFile) {
	CURL* pCurl = curl_easy_init();
	int curlResponse = -1;
	int authStatus = PAM_AUTH_ERR;
	if (!pCurl) {
		PAM_DEBUG("Error initialising curl\n");
		return PAM_AUTH_ERR;
	}

	HttpResponse* httpResponse = malloc(sizeof(HttpResponse));
	char* pCredentials;
	int len = strlen(pUsername) + strlen(pPassword) + 42;

	pCredentials = malloc(len);
	sprintf(pCredentials, "{\"account\":{\"username\":\"%s\",\"password\":\"%s\"}}", pUsername, pPassword);

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
/*
	curl_easy_setopt(pCurl, CURLOPT_RANDOM_FILE, "/dev/urandom");
	curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2);
	curl_easy_setopt(pCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
*/

	curlResponse = curl_easy_perform(pCurl);
	curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &httpResponse->responseCode);
	HttpError *error = &httpResponse->err;
	error->error = (curlResponse != CURLE_OK);
	error->msg = curl_easy_strerror(curlResponse);

	if (httpResponse->err.error) {
		authStatus = PAM_AUTH_ERR;
		PAM_DEBUG("%s\n", httpResponse->err.msg);
	} else {
		PAM_DEBUG("Response status: %ld\n", httpResponse->responseCode);
		if (httpResponse->responseCode == 200) {
			authStatus = PAM_SUCCESS;
		} else if (httpResponse->responseCode == 401) {
			authStatus = PAM_PERM_DENIED;
		} else {
			authStatus = PAM_AUTH_ERR;
			PAM_DEBUG("%s\n", "Bad HTTP response code");
		}
	}

	memset(pCredentials, '\0', len);
	free(pCredentials);
	curl_easy_cleanup(pCurl);
	curl_slist_free_all(pHeaders);
	free(httpResponse);

	PAM_DEBUG("Auth status: %d\n", authStatus);

	return authStatus;
}

static int get_user_name(pam_handle_t *pamh, const char** userName) {
	int status;
	int retval = pam_get_user(pamh, userName, NULL);
	if (retval != PAM_SUCCESS || userName == NULL || *userName == NULL) {
		status = PAM_AUTHINFO_UNAVAIL;
		PAM_DEBUG("User name lookup failed\n");
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
	int ret = 0;

	const char* pUsername = NULL;
	const char* pUrl = NULL;
	const char* pCaFile = NULL;

	struct pam_message msg;
	struct pam_conv* pItem;
	struct pam_response* pResp;
	const struct pam_message* pMsg = &msg;

	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = "Flight Center password: ";

	int statusCode = get_user_name(pamh, &pUsername);
	if (statusCode != PAM_SUCCESS) {
		return statusCode;
	}

	pUrl = getArg("url", argc, argv);
	if (!pUrl) {
		return PAM_AUTH_ERR;
	}

	pCaFile = getArg("cafile", argc, argv);
	if (pam_get_item(pamh, PAM_CONV, (const void**)&pItem) != PAM_SUCCESS || !pItem) {
		PAM_DEBUG("Couldn't get pam_conv\n");
		return PAM_AUTH_ERR;
	}

	pItem->conv(1, &pMsg, &pResp, pItem->appdata_ptr);

	ret = PAM_SUCCESS;

	if (authenticate_user(pUrl, pUsername, pResp[0].resp, pCaFile) != 0) {
		ret = PAM_AUTH_ERR;
	}

	memset(pResp[0].resp, 0, strlen(pResp[0].resp));
	free(pResp);

	return ret;
}

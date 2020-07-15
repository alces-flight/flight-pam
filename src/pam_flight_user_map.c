/*
  Pam module to set the flight user name from the unix user name and given map
  file.  The user name in the pam stack is not altered.

  Compile as

     gcc pam_flight_user_map.c -shared -lpam -fPIC -o pam_flight_user_map.so

  And create /etc/security/flight_user_map.conf with the
  desired mapping in the format:  unix_user_name: flight_user_name
=========================================================
#comments and empty lines are ignored
john: jack
bob:  admin
top:  accounting
=========================================================

You can use a different location for the user map file by adding the
`mapfile` option like this
=========================================================
auth            optional        pam_flight_user_map.so mapfile=/path/to/map.conf
=========================================================

If something doesn't work as expected you can get verbose
comments with the 'debug' option like this
=========================================================
auth            optional        pam_flight_user_map.so debug
=========================================================
These comments are written to the syslog as 'authpriv.debug'
and usually end up in /var/log/secure file.
*/

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define DEFAULT_FILENAME "/etc/security/flight_user_map.conf"
#define skip(what) while (*s && (what)) s++
#define SYSLOG_DEBUG if (mapargs.debug) pam_syslog

const char *
str_skip_icase_prefix(const char *str, const char *prefix)
{
  size_t prefix_len = strlen(prefix);
  return strncasecmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

static const char debug_keyword[]= "debug";
static const char mapfile_prefix[]= "mapfile=";

struct flight_user_map_args {
        const char *filename;
        int debug;
};

static int
parse_args(pam_handle_t *pamh, struct flight_user_map_args *mapargs,
           int argc, const char **argv)
{
    mapargs->filename = DEFAULT_FILENAME;
    mapargs->debug = 0;

    int i;
    for (i=0; i<argc; ++i) {
        const char *str;
        if (strcasecmp(argv[i], debug_keyword) == 0) {
            mapargs->debug = 1;
            continue;
        }
        str = str_skip_icase_prefix(argv[i], mapfile_prefix);
        if (str != NULL) {
          mapargs->filename = str;
          continue;
        }
        pam_syslog(pamh, LOG_ERR, "unrecognized option [%s]", argv[i]);
    }
    return 1;
}


void data_cleanup(pam_handle_t *pamh, void *data, int error_status)
{
    if (data) {
            /* junk it */
            (void) free(data);
    }
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
  struct flight_user_map_args mapargs;
  int pam_err, line= 0;
  const char *username;
  char buf[256];
  FILE *f;

  memset(&mapargs, '\0', sizeof(mapargs));
  if (!parse_args(pamh, &mapargs, argc, argv)) {
    pam_syslog(pamh, LOG_ERR, "failed to parse the module arguments");
    return PAM_ABORT;
  }

  SYSLOG_DEBUG(pamh, LOG_DEBUG, "Opening file '%s'.\n", mapargs.filename);

  f= fopen(mapargs.filename, "r");
  if (f == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Cannot open '%s'\n", mapargs.filename);
    return PAM_SYSTEM_ERR;
  }

  pam_err = pam_get_item(pamh, PAM_USER, (const void**)&username);
  if (pam_err != PAM_SUCCESS)
  {
    pam_syslog(pamh, LOG_ERR, "Cannot get username.\n");
    goto ret;
  }

  SYSLOG_DEBUG(pamh, LOG_DEBUG, "Incoming username '%s'.\n", username);

  while (fgets(buf, sizeof(buf), f) != NULL)
  {
    char *s= buf, *from, *to, *end_from, *end_to;
    /* int check_group; */
    int cmp_result;

    line++;

    skip(isspace(*s));
    if (*s == '#' || *s == 0) continue;
    from= s;
    skip(isalnum(*s) || (*s == '_') || (*s == '.') || (*s == '-') ||
         (*s == '$') || (*s == '\\') || (*s == '/'));
    end_from= s;
    skip(isspace(*s));
    if (end_from == from || *s++ != ':') goto syntax_error;
    skip(isspace(*s));
    to= s;
    skip(isalnum(*s) || (*s == '_') || (*s == '.') || (*s == '-') ||
         (*s == '$'));
    end_to= s;
    if (end_to == to) goto syntax_error;

    *end_from= *end_to= 0;

    cmp_result= (strcmp(username, from) == 0);
    SYSLOG_DEBUG(pamh, LOG_DEBUG, "Check if username '%s': %s\n",
                                    from, cmp_result ? "YES":"NO");
    if (cmp_result)
    {
      char *mappedData = malloc(strlen(to));
      if (mappedData == NULL) {
        pam_syslog(pamh, LOG_CRIT, "pam_flight_user_map: cannot allocate mappedData");
        pam_err = PAM_BUF_ERR;
        goto ret;
      }
      strcpy(mappedData, to);
      pam_err = pam_set_data(pamh, "pam_flight_user_map_data", mappedData, data_cleanup);
      SYSLOG_DEBUG(pamh, LOG_DEBUG, 
          (pam_err == PAM_SUCCESS) ? "User mapped as '%s'\n" :
                                     "Couldn't map as '%s'\n", mappedData);
      goto ret;
    }
  }

  SYSLOG_DEBUG(pamh, LOG_DEBUG, "User not found in the list.\n");
  pam_err= PAM_USER_UNKNOWN;
  goto ret;

syntax_error:
  pam_syslog(pamh, LOG_ERR, "Syntax error at %s:%d", mapargs.filename, line);
  pam_err= PAM_SYSTEM_ERR;
ret:
  fclose(f);

  return pam_err;
}


int pam_sm_setcred(pam_handle_t *pamh, int flags,
                   int argc, const char *argv[])
{

    return PAM_SUCCESS;
}

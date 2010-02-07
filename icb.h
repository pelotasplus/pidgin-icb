/*
 * Copyright (c) 2005 Aleksander Piotrowski <aleksander.piotrowski@nic.com.pl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef ICB_H
#define ICB_H

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <glib.h>
#include <fcntl.h>

#define PURPLE_PLUGINS

/* from libpurple/internal.h */
#ifndef G_GNUC_NULL_TERMINATED
#  if __GNUC__ >= 4
#    define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#  else
#    define G_GNUC_NULL_TERMINATED
#  endif /* __GNUC__ >= 4 */
#endif /* G_GNUC_NULL_TERMINATED */

/* pidgin headers */
#include <version.h>
#include <xmlnode.h>
#include <account.h>
#include <accountopt.h>
#include <debug.h>
#include <request.h>
#include <cipher.h>

#ifdef ENABLE_NLS
#  include <locale.h>
#  include <libintl.h>
#  define _(x) gettext(x)
#  ifdef gettext_noop
#    define N_(String) gettext_noop (String)
#  else
#    define N_(String) (String)
#  endif
#else
#  define N_(String) (String)
#  define _(x) ((char *)x)
#endif

#define ICB_VERSION "20070505"

#define ICB_PACKET_SIZE     255
#define ICB_MAX_DATA_SIZE   230 /* XXX Max value is 252 *but* some servers
                                 * don't allow that big packets
                                 */
#define ICB_MAX_NO_FIELDS   20
#define ICB_NICKLEN         12
#define ICB_BUFSIZE         4096

#define ICB_SEPARATOR        '\001'
#define ICB_CMD_LOGIN         'a'
#define ICB_CMD_OPEN_MSG      'b'
#define ICB_CMD_PERSONAL_MSG  'c'
#define ICB_CMD_STATUS_MSG    'd'
#define ICB_CMD_ERROR         'e'
#define ICB_CMD_EXIT          'g'
#define ICB_CMD_COMMAND       'h'
#define ICB_CMD_COMMAND_RESP  'i'
#define ICB_CMD_PROTO_VERSION 'j'
#define ICB_CMD_MSG           'm'
#define ICB_CMD_WHO           'w'

#define ICB_SERVICES_NAME	"server"

#define ICB_STAT_JOIN "You are now in group"
#define ICB_STAT_JOIN_LEN 20
#define ICB_STAT_SIGNON "Sign-on"
#define ICB_STAT_SIGNON_LEN 7
#define ICB_STAT_SIGNOFF "Sign-off"
#define ICB_STAT_SIGNOFF_LEN 8
#define ICB_STAT_MOD_SIGNOFF "group moderator signed off"
#define ICB_STAT_ARRIVE "Arrive"
#define ICB_STAT_ARRIVE_LEN 6
#define ICB_STAT_DEPART "Depart"
#define ICB_STAT_DEPART_LEN 6
#define ICB_NICK_CHANGE "Name"
#define ICB_NICK_CHANGE_LEN 4
#define ICB_STAT_BOOTED "Boot"
#define ICB_STAT_BOOTED_LEN 4
#define ICB_STAT_TOPIC "Topic"
#define ICB_STAT_TOPIC_LEN 5
#define ICB_STAT_PASS "Pass"
#define ICB_STAT_PASS_LEN 4 
#define ICB_STAT_PASS_AUTO "is now mod"

#define ICB_FIRST_CHAT_ID 1

#define ICB_TOPIC "Topic: "

#define ICB_CONNECT_STEPS   3

#define ICB_DEFAULT_SERVER "default.icb.net"
#define ICB_DEFAULT_PORT   7326
#define ICB_DEFAULT_GROUP  "1"

enum wl_mode {
	WL_MODE_DEFAULT,
	WL_MODE_GROUP_LIST,
	WL_MODE_GET_INFO
};

typedef struct {
	PurpleAccount *account;
	int          fd;
	char        *server;
	char        *user;
	const char  *login_id;
	int          port;
	char        *group;
	int          chat_id;
	enum wl_mode wl;		/* What to do with wl response */
	char         wl_nick[256];	/* What to do with wl response */
#if 0
	GString     *motd;		/* MOTD.  First bunch of "co"s sent by server right after
					 * user logs in.
					 */
	int          motd_received;	/* true/false if MOTD has been received.  Right now
					 * MOTD is everything what server sends us as "co"
					 * "i" message until we 
					 */
#endif
} IcbSession;

typedef struct {
	int    length;
	char   command;
	char **fields;
	int    nof;
} IcbPacket;

static void        icb_dump_packet(IcbPacket *);
static void        icb_free_packet(IcbPacket **);
static IcbPacket  *icb_parse_buf();
static void        icb_login_cb(gpointer data, gint source, const gchar *error_message);
static int         icb_send(IcbSession *, char, int, ...);
static void        icb_login(PurpleAccount *);
static void        icb_close(PurpleConnection *);
static void        icb_input_cb(gpointer, gint, PurpleInputCondition);
static void        icb_dump_buf(char *, int);
static void        icb_join_chat(PurpleConnection *, GHashTable *);
static void        icb_leave_chat(PurpleConnection *, int);
static GList      *icb_chat_info(PurpleConnection *);
static GHashTable *icb_chat_info_defaults(PurpleConnection *, const char *);

#define SET_WL_MODE(i, mode) purple_debug_info("icb", "changing wl mode from %d to %d\n", (i)->wl, mode); (i)->wl = mode

#endif /* ICB_H */

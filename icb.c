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

/* vim:ts=4 */

#define PURPLE_PLUGINS

#include "icb.h"

#include <libpurple/cmds.h>

/*
 * Keep alives will be sent after KEEPALIVE_TIMEOUT seconds of
 * inactivity.
 */
#define KEEPALIVE_TIMEOUT 150

static char  icb_input_buf[ICB_BUFSIZE+1];
static char *icb_input_pos = icb_input_buf;
static int   icb_input_fill = 0;
static int   chat_id = ICB_FIRST_CHAT_ID;

int
icb_get_new_chat_id()
{
	return chat_id++;
}

/* XXX Maybe this could be used?
 * gconv = purple_find_conversation_with_account(name, gc->account);
 */
static PurpleConversation *
icb_get_current_group(PurpleAccount *account, int chat_id)
{
	GList *l = NULL;
	PurpleConversation *conv = NULL;

	for (l = purple_get_conversations(); l != NULL; l = l->next) {
                conv = (PurpleConversation *)l->data;

                if (purple_conversation_get_account(conv) == account
		    && purple_conversation_get_chat_data(conv) != NULL
		    && chat_id == purple_conv_chat_get_id(purple_conversation_get_chat_data(conv))) {
			return conv;
		}
        }

	return NULL;
}

static GList *
icb_status_types(PurpleAccount *account)
{
        PurpleStatusType *type;
        GList *types = NULL;

	purple_debug(PURPLE_DEBUG_INFO, "icb", "-> icb_status_types\n");

        type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "available",
                        _("Available"), TRUE, TRUE, FALSE, "message", _("Message"),
                        purple_value_new(PURPLE_TYPE_STRING), NULL);
        types = g_list_append(types, type);

        type = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE, "offline",
                        _("Offline"), TRUE, TRUE, FALSE, "message", _("Message"),
                        purple_value_new(PURPLE_TYPE_STRING), NULL);
        types = g_list_append(types, type);

	purple_debug(PURPLE_DEBUG_INFO, "icb", "<- icb_status_types\n");

	return types;
}

void
icb_dump_packet(IcbPacket *packet)
{
	int i;

	purple_debug_info("icb", "-> icb_dump_packet\n");

	purple_debug_info("icb", "length:  %d\n", packet->length);
	purple_debug_info("icb", "command: %c\n", packet->command);
	for (i = 0; i < packet->nof; i++) {
		purple_debug_info("icb", "field %d: %ld \"%s\"\n",
			i, (long) strlen(packet->fields[i]), packet->fields[i]);
	} 

	purple_debug_info("icb", "<- icb_dump_packet\n");
}

void
icb_free_packet(IcbPacket **packet)
{
	IcbPacket *tmp = *packet;
	int        i;

	for (i = 0; i < tmp->nof; i++) {
		free(tmp->fields[i]);
	} 
	free(tmp);
	*packet = NULL;
}

void
icb_dump_buf(char *buf, int len)
{
	int i;

	char *out = (char *) calloc(1, len+1);
	if (!out) {
		return;
	}

	for (i = 0; i < len; i++) {
		*(out+i) = *(buf+i) == ICB_SEPARATOR ? ',' : *(buf+i);
	}	

	/* Replace first char of buf (size) with X as it could have
	 * a non-printable value
	 */
	*out = 'X';

	purple_debug_info("icb", "len= %d, buf=\"%s\"\n", len, out);
	free(out);
}

IcbPacket *
icb_parse_buf()
{
	char          *separator, *tmpbuf;
	unsigned char size;
	IcbPacket     *packet = NULL;

	purple_debug_info("icb", "-> icb_parse_buf\n");

	/* There has to be at least two chars in buffer: size and command */
	if (icb_input_fill < 2) {
		purple_debug_info("icb", "Buffer is to short.\n");
		return NULL;
	}

	icb_dump_buf(icb_input_pos, icb_input_fill);

	/* Check if there is a full packet in buffer.
	 * First char is a packet size, so let's check if
	 * buffer size isn't to small.
	 */
	if (*icb_input_pos > icb_input_fill) {
		purple_debug_info("icb", "Looks like buffer is not filled with full packet\n");
		return NULL;
	}

	packet = (IcbPacket *) calloc(1, sizeof(IcbPacket));
	if (!packet) {
		purple_debug_info("icb", "calloc(IcbPacket)\n");
		purple_debug_info("icb", "<- icb_parse_buf\n");
		return NULL;
	}

	size = * (unsigned char *) icb_input_pos; /* size of the packet */
	tmpbuf = icb_input_pos+1; /* Command sent in packet */

	packet->nof = 0;
	packet->fields = (char **) calloc(1, ICB_MAX_NO_FIELDS*sizeof(char *));
	packet->length = size;
	packet->command = *tmpbuf++;

	separator = tmpbuf;
	while (tmpbuf - icb_input_pos < packet->length + 1) {
		/* new field */
		if ((*tmpbuf == ICB_SEPARATOR || *tmpbuf == '\0')
		    && separator != tmpbuf) {
			*tmpbuf = '\0';
			packet->fields[packet->nof++] = strdup(separator);
			separator = tmpbuf+1;
		}
		tmpbuf++;
	}

	icb_input_pos = tmpbuf;
	icb_input_fill -= packet->length + 1;
	
	purple_debug_info("icb", "<- icb_parse_buf\n");

	return packet;
}

void
icb_login_cb(gpointer data, gint source, const gchar *error_message)
{
	PurpleConnection *gc = data;
	IcbSession     *icb = gc->proto_data;

	purple_debug(PURPLE_DEBUG_INFO, "icb", "-> icb_login_cb\n");

	if (source < 0) {
		purple_connection_error(gc, _("Couldn't connect to host"));
		return;
	}
	
	fcntl(source, F_SETFL, 0);
	icb->fd = source;

	purple_connection_update_progress(gc, _("Reading protocol packet"), 2, ICB_CONNECT_STEPS);

	gc->inpa = purple_input_add(icb->fd, PURPLE_INPUT_READ, icb_input_cb, gc);

	icb->sr_time = time(NULL);

	purple_debug_info("icb", "<- icb_login_cb\n");
}

/* ICB packet is:
 *   size -> one byte
 *   command -> one byte
 *   data -> 253 bytes
 *     -> field 0
 *     -> seperator
 *     -> field 1
 *     -> [and so on]
 *     -> NUL
 */
int
icb_send(IcbSession *icb, char command, int params, ...)
{
	const char *field;
	char        packet[ICB_PACKET_SIZE];
	char       *pos = packet;
	va_list     arg;
	int         fieldlen, ret, size;

	purple_debug_info("icb", "-> icb_send\n");
	if (icb->fd < 0) {
		purple_debug_info("icb", "<- icb_send: icb->fd < 0");
		return -1;
	}

	memset(packet, '\0', sizeof(packet));

	// size of packet (filled with dummy value for now) 
	*pos++ = '-';

	// command	
	*pos = command;

	// amount of data in buffer
	size = 2;

	// fields
	va_start(arg, params);
	while (params-- > 0) {
		field = va_arg(arg, const char *);
		if (field != NULL) {
			fieldlen = strlen(field);
			// -1 to leave space for NUL at the end of buffer
			if (fieldlen + size > ICB_PACKET_SIZE -1) {
				purple_debug_info("icb", "<- icb_send: too much data to write");
				va_end(arg);
				return -1;
			}

			// field data
			strncpy(&packet[size], field, fieldlen);
			size += fieldlen;
		} else
			purple_debug_info("icb", "Skipping NULL param");

		// separator
		if (params != 0) {
			packet[size] = ICB_SEPARATOR;
			size++;
		}
	}
	va_end(arg);

	// packet size
	*packet = size;

	icb_dump_buf(packet, strlen(packet));

	ret = write(icb->fd, packet, size + 1);
	if (ret < 0) {
		purple_debug_info("icb", "write(): %d, %s\n", errno, strerror(errno));
		purple_connection_error(purple_account_get_connection(icb->account),
			_("Server has disconnected"));
	} else
		icb->sr_time = time(NULL);

	purple_debug_info("icb", "<- icb_send %d byte(s)\n", ret);

	return ret;
}

static void
icb_login(PurpleAccount *account)
{
	PurpleConnection  *gc;
	IcbSession      *icb;
	PurpleProxyConnectData *err;
	const char      *user;
	char           **userparts;

	purple_debug_info("icb", "-> icb_login\n");

	gc = purple_account_get_connection(account);
	gc->flags |= PURPLE_CONNECTION_NO_NEWLINES;

	gc->proto_data = icb= g_new0(IcbSession, 1);

	icb->account = account;
	icb->chat_id = icb_get_new_chat_id();

	memset(icb_input_buf, '\0', sizeof(icb_input_buf));
	icb_input_pos = icb_input_buf;
	icb_input_fill = 0;

	user = purple_account_get_username(account);
	userparts = g_strsplit(user, "@", 2);
	purple_connection_set_display_name(gc, userparts[0]);

	icb->user = g_strdup(userparts[0]);
	icb->server = g_strdup(userparts[1]);

	g_strfreev(userparts);

	icb->port = purple_account_get_int(account, "port", ICB_DEFAULT_PORT);
	icb->login_id = purple_account_get_string(account, "login_id", icb->user);

	purple_connection_update_progress(gc, _("Connecting"), 1, ICB_CONNECT_STEPS);

	err = purple_proxy_connect(gc, account, icb->server, icb->port, icb_login_cb, gc);
	if (!err || !account->gc) {
		purple_connection_error(gc, _("Couldn't create socket"));
		purple_debug_info("icb", "<- icb_login\n");
		return;
	}

	purple_debug_info("icb", "<- icb_login\n");
}

void
icb_show_get_info(IcbSession *icb, IcbPacket *packet)
{
	PurpleNotifyUserInfo *user_info;
	time_t idle;
	gchar *timex;

	/* wl
	 * icb: command: i
	 * icb: field 0: 2 "wl"
	 * icb: field 1: 1 "m" -- mod
	 * icb: field 2: 8 "pelotass" -- nickname
	 * icb: field 3: 3 "355" -- idle (seconds)
	 * icb: field 4: 1 "0" -- response time (not used)
	 * icb: field 5: 10 "1134676594" -- login time (time_t since 19700101)
	 * icb: field 6: 8 "pelotass" -- userid
	 * icb: field 7: 14 "[84.10.69.233]" -- hostid
	 * icb: field 8: 4 "(nr)" -- register info
	 */
	
	user_info = purple_notify_user_info_new();

	purple_notify_user_info_add_pair(user_info, _("Nickname"), packet->fields[2]);
	purple_notify_user_info_add_pair(user_info, _("Registration"),
		strcmp(packet->fields[8], "(nr)") == 0 ? _("not registered") : _("registered"));
	purple_notify_user_info_add_pair(user_info, _("Username"), packet->fields[6]);
	purple_notify_user_info_add_pair(user_info, _("Hostname"), packet->fields[7]);

	idle = atoi(packet->fields[3]);
	if (idle > 0) {
		timex = purple_str_seconds_to_string(idle);
		purple_notify_user_info_add_pair(user_info, _("Idle for"), timex);
		g_free(timex);
	}

	idle = atoi(packet->fields[5]);
	purple_notify_user_info_add_pair(user_info, _("Online since"), ctime(&idle));

	purple_notify_userinfo(purple_account_get_connection(icb->account), packet->fields[2], user_info, NULL, NULL);
		
	purple_notify_user_info_destroy(user_info);
}

void
icb_input_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	IcbSession *icb = gc->proto_data;
	IcbPacket *packet = NULL;

	int len, ret;
	char *tmp;

	purple_debug_misc("icb", "-> icb_input_cb: fd=%d\n", icb->fd);

	if (icb->fd < 0) {
		purple_debug_info("icb", "icb->fd < 0");
		return;
	}

	len = read(icb->fd, icb_input_pos + icb_input_fill,
		ICB_BUFSIZE - (icb_input_pos - icb_input_buf + icb_input_fill));
	purple_debug_info("icb", "Read() got %d chars\n", len);
	if (len < 0) {
		purple_debug_info("icb", "errno=%d strerror=%s\n", errno, strerror(errno));
		purple_connection_error(gc, _("Read error"));
		return;
	} else if (len == 0) {
		purple_connection_error(gc, _("Server has disconnected"));
		return;
	}

	icb_input_fill += len;
	purple_debug_info("icb", "Now buffer is filled with %d char(s)\n", icb_input_fill);

	while (icb_input_fill > 0 && (packet = icb_parse_buf()) != NULL) {
		icb->sr_time = time(NULL);
		icb_dump_packet(packet);
		switch (packet->command) {
			case ICB_CMD_PROTO_VERSION:
				purple_connection_update_progress(gc,
					_("Sending login information"), 2,
	                        	ICB_CONNECT_STEPS);

				if (gc->account->password && *gc->account->password) {
					ret = icb_send(icb, ICB_CMD_LOGIN, 5, icb->login_id, icb->user,
						purple_account_get_string(gc->account, "group", ICB_DEFAULT_GROUP),
						"login", gc->account->password);
				} else {
					ret = icb_send(icb, ICB_CMD_LOGIN, 4, icb->login_id, icb->user,
						purple_account_get_string(gc->account, "group", ICB_DEFAULT_GROUP),
						"login");
				}
				if (ret < 0) {
					purple_connection_error(gc,
						_("Error sending login information"));
					icb_free_packet(&packet);
					return;
				}

				break;
			case ICB_CMD_LOGIN:
				purple_connection_set_state(gc, PURPLE_CONNECTED);
				break;
			case ICB_CMD_ERROR:
				if (packet->nof == 1) {
					purple_notify_warning(gc, NULL, _("Error message from server"), packet->fields[0]);
				}
				break;
			case ICB_CMD_EXIT:
				purple_connection_error(gc, "Received Exit packet. Closing connection.");
				break;
			/*
			 * icb: command: c
			 * icb: field 0: 7 "pelotas"
			 * icb: field 1: 2 "Hi"
			 */
			case ICB_CMD_PERSONAL_MSG:
				if (packet->nof >= 1) {
					char *msg;

					msg = g_markup_escape_text(packet->nof == 1 ? "" : packet->fields[1], -1);
					serv_got_im(gc, packet->fields[0], msg, 0, time(NULL));
					g_free(msg);
				}
				break;
			case ICB_CMD_OPEN_MSG:
				if (packet->nof == 2) {
					char *msg;

					msg = g_markup_escape_text(packet->fields[1], -1);
					serv_got_chat_in(gc, icb->chat_id, packet->fields[0], 0, msg, time(NULL));
					g_free(msg);
				}
				break;
			case ICB_CMD_STATUS_MSG:
				/* Just joined a group */
				if (packet->nof == 2 && 
				    strncmp(packet->fields[1], ICB_STAT_JOIN, ICB_STAT_JOIN_LEN) == 0) {
					PurpleConversation *conv = NULL;
					char              group[ICB_PACKET_SIZE], *name_end, *name_start;

					/* Looking for a group name */
					memset(group, '\0', sizeof(group));

					/* +1 to skip space after ICB_STAT_JOIN */
					name_start = packet->fields[1] + ICB_STAT_JOIN_LEN + 1;
					name_end = name_start;
					while (((name_end - packet->fields[1]) < strlen(packet->fields[1])) && *name_end != ' ') {
						name_end++;
					}
					strncpy(group, packet->fields[1] + ICB_STAT_JOIN_LEN + 1,
					        name_end - name_start);

					/* Leave previous group.  You can only join one group on ICB */
					conv = icb_get_current_group(gc->account, icb->chat_id);
					if (conv) {
						purple_debug_info("icb", "Leaving previous conv %d\n", icb->chat_id);
						serv_got_chat_left(gc, icb->chat_id);
						free(icb->group);
					}

					/* Joining new group and getting user list */
					icb->group = strdup(group);
					icb->chat_id = icb_get_new_chat_id();
					purple_debug_info("icb", "Joined chat %d\n", icb->chat_id);
					serv_got_joined_chat(gc, icb->chat_id, group);
					SET_WL_MODE(icb, WL_MODE_GROUP_LIST);
					icb_send(icb, ICB_CMD_COMMAND, 2, "w", ".");
				/* Somebody has joined current group */
				} else if (packet->nof == 2 &&
				           ((strncmp(packet->fields[0], ICB_STAT_ARRIVE, ICB_STAT_ARRIVE_LEN) == 0)
					   || (strncmp(packet->fields[0], ICB_STAT_SIGNON, ICB_STAT_SIGNON_LEN) == 0))) {
					PurpleConversation *conv = NULL;
					char              user[ICB_PACKET_SIZE], *name_end, *name_start;
					int               len;

					/* Get current group */
					conv = icb_get_current_group(gc->account, icb->chat_id);
					if (!conv)
						break;
					
					/* Looking for a group name */
					memset(user, '\0', sizeof(user));

					len = strlen(packet->fields[1]);
					name_start = packet->fields[1];
					name_end = name_start;
					while (((name_end - packet->fields[1]) < len) && *name_end != ' ') {
						name_end++;
					}
					strncpy(user, packet->fields[1], name_end - name_start);
	
					purple_conv_chat_add_user(PURPLE_CONV_CHAT(conv), user,
						NULL, PURPLE_CBFLAGS_NONE, TRUE);
				/* Somebody has left current group */
				/*
				 * icb: field 0: 8 "Sign-off"
				 * icb: field 1: 42 "alek (alek@[84.10.69.233]) has signed off."
				 *               45 "Your group moderator signed off. (No timeout)"
				 */
				} else if (packet->nof == 2 &&
				           ((strncmp(packet->fields[0], ICB_STAT_DEPART, ICB_STAT_DEPART_LEN) == 0)
				           || (strncmp(packet->fields[0], ICB_STAT_SIGNOFF, ICB_STAT_SIGNOFF_LEN) == 0))) {
					PurpleConversation *conv = NULL;
					char              user[ICB_PACKET_SIZE], *name_end, *name_start;
					int               len;

					/* Get current group */
					conv = icb_get_current_group(gc->account, icb->chat_id);
					if (!conv)
						break;
		
					/* My moderator just left, bogus Sign-off message. Ignore it */
					if (strstr(packet->fields[1], ICB_STAT_MOD_SIGNOFF) != NULL) {
						break;
					}

					/* Looking for a group name */
					memset(user, '\0', sizeof(user));

					len = strlen(packet->fields[1]);
					name_start = packet->fields[1];
					name_end = name_start;
					while (((name_end - packet->fields[1]) < len) && *name_end != ' ') {
						name_end++;
					}
					strncpy(user, packet->fields[1], name_end - name_start);
	
					purple_conv_chat_remove_user(PURPLE_CONV_CHAT(conv), user, NULL);
				/* Somebody has changed nick */
				} else if (packet->nof == 2 &&
					(strncmp(packet->fields[0], ICB_NICK_CHANGE, ICB_NICK_CHANGE_LEN)  == 0)) {
					char *orig_name, *new_name, *tmp;
					PurpleConversation *conv;
					
					/* Who is changing nick .. */
					orig_name = packet->fields[1];
					tmp = strchr(packet->fields[1], ' ');
					if (tmp == NULL) {
						purple_notify_warning(gc, NULL, _("Error message"), "Cannot get original nick");
						break;
					}
					*tmp = '\0';

					/* .. and what's his new nick */
					new_name = strrchr(tmp + 1, ' ');
					if (new_name == NULL) {
						purple_notify_warning(gc, NULL, _("Error message"), "Cannot get new nick");
						break;
					}
					new_name++;
	
					if (!purple_utf8_strcasecmp(orig_name, purple_connection_get_display_name(gc))) {
						purple_connection_set_display_name(gc, new_name);
					}

					/* Change user's nick in the group we belngs to */
					conv = icb_get_current_group(gc->account, icb->chat_id);
					if (conv) {
						purple_conv_chat_rename_user(PURPLE_CONV_CHAT(conv), orig_name, new_name);
					}

					/* ... and in the private IM window too */
					conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, orig_name, gc->account);
					if (conv) {
						purple_conversation_set_name(conv, new_name);
					}
				/* Someone has been booted */
				} else if (packet->nof == 2 &&
					(strncmp(packet->fields[0], ICB_STAT_BOOTED, ICB_STAT_BOOTED_LEN)  == 0)) {
					char name[ICB_MAX_DATA_SIZE];
					int namelen = 0;
					PurpleConversation *conv;

					/* First space ends nick */
					tmp = strchr(packet->fields[1], ' ');
					if (tmp == NULL) {
						purple_notify_warning(gc, NULL, _("Error"),
							"No space after nick in boot command.\n");
						break;
					}

					namelen = tmp - packet->fields[1];
					if ((namelen < 0) || (namelen > ICB_MAX_DATA_SIZE)) {
						purple_notify_warning(gc, NULL, _("Error"),
							"Name in boot command has wrong length.\n");
						break;
					}
					
					strncpy(name, packet->fields[1], namelen);
					name[namelen] = '\0';

					conv = icb_get_current_group(gc->account, icb->chat_id);

					if (!purple_utf8_strcasecmp(purple_connection_get_display_name(gc), name)) {
						purple_conv_chat_write(PURPLE_CONV_CHAT(conv), "?", "You have been booted",
							PURPLE_MESSAGE_SYSTEM, time(NULL));
						/* We could wait for another boot packet that would tell us who booted us. */
						serv_got_chat_left(gc, icb->chat_id);
					} else {
						purple_conv_chat_write(PURPLE_CONV_CHAT(conv), "aa", packet->fields[1],
							PURPLE_MESSAGE_SYSTEM, time(NULL));
					}		
				} else if (packet->nof == 2 &&
					(strncmp(packet->fields[0], ICB_STAT_TOPIC, ICB_STAT_TOPIC_LEN)  == 0)) {
					char *name, *topic, *tmp;
					PurpleConversation *conv;

					/* Who has changed the topic */
					name = packet->fields[1];
					tmp = strchr(packet->fields[1], ' ');
					if (tmp == NULL) {
						purple_notify_warning(gc, NULL, _("Error"),
							"Cannot find who has changed topic.\n");
						break;
					}
					*tmp = '\0';

					/* Looking for the begining of the new topic ... */
					tmp = strchr(++tmp, '"');
					if (tmp == NULL) {
						purple_notify_warning(gc, NULL, _("Error"),
							"Cannot find new topic.\n");
						break;
					}
					topic = ++tmp;
					
					/* ... and it's end */
					tmp = strrchr(topic, '"');
					if (tmp == NULL) {
						purple_notify_warning(gc, NULL, _("Error"),
							"Cannot find the end of new topic.\n");
						break;
					}
					*tmp = '\0';

					tmp = g_markup_escape_text(topic, -1);

					conv = icb_get_current_group(gc->account, icb->chat_id);

					/* Now it's time to set the new topic */
					purple_conv_chat_set_topic(PURPLE_CONV_CHAT(conv), name, topic);
					name = g_strdup_printf(_("%s has changed the topic to: %s"), name, tmp);
                			purple_conv_chat_write(PURPLE_CONV_CHAT(conv), "", name,
						PURPLE_MESSAGE_SYSTEM, time(NULL));
					g_free(tmp);
					g_free(name);
				/*
				 * icb: command: d
				 * icb: field 0: 4 "Pass"
				 * icb: field 1: 38 "pelotass has passed moderation to alek"
				 *               20 "pelotass is now mod."
				 */
				} else if (packet->nof == 2 &&
					(strncmp(packet->fields[0], ICB_STAT_PASS, ICB_STAT_PASS_LEN)  == 0)) {
					char old_mod[ICB_MAX_DATA_SIZE], *new_mod;
					PurpleConversation *conv;

					conv = icb_get_current_group(gc->account, icb->chat_id);

					memset(old_mod, '\0', sizeof(old_mod));
					tmp = strchr(packet->fields[1], ' ');
					if (tmp == NULL) {
						purple_notify_warning(gc, NULL, _("Error"),
							"Cannot find who has passed mod privileges.\n");
						break;
					}
					strncpy(old_mod, packet->fields[1], tmp - packet->fields[1]);

					if (strstr(++tmp, ICB_STAT_PASS_AUTO) != NULL) {
						/* old_mod points to new_mod in this case */
						new_mod = old_mod;
						goto moderator_just_left;
					}

					tmp = strrchr(++tmp, ' ');
					if (tmp == NULL) {
						purple_notify_warning(gc, NULL, _("Error"),
							"Cannot find new moderator.\n");
						break;
					}
					new_mod = ++tmp;
					
					purple_conv_chat_user_set_flags(PURPLE_CONV_CHAT(conv), old_mod, PURPLE_CBFLAGS_NONE);
moderator_just_left:
					purple_conv_chat_user_set_flags(PURPLE_CONV_CHAT(conv), new_mod, PURPLE_CBFLAGS_OP);
                			purple_conv_chat_write(PURPLE_CONV_CHAT(conv), "", packet->fields[1],
							PURPLE_MESSAGE_SYSTEM, time(NULL));
				} else if (packet->nof == 2) {                                                                                                                       
					char *tmp;                                                                                                                                   
					PurpleConversation *conv;                                                                                                                      

					conv = icb_get_current_group(gc->account, icb->chat_id);                                                                                     

					tmp = g_strdup_printf(_("%s: %s"), packet->fields[0], packet->fields[1]);                                                                    
					serv_got_im(gc, ICB_SERVICES_NAME, tmp, 0, time(NULL));
#if 0
					purple_conv_chat_write(PURPLE_CONV_CHAT(conv), "", tmp,                                                                                          
							PURPLE_MESSAGE_SYSTEM, time(NULL));                                                                                                    
#endif
					g_free(tmp);
					break;
				}
			case ICB_CMD_COMMAND_RESP:
				/* group listing: one wl entry for each member
				 * icb: command: i
				 * icb: field 0: 2 "wl"
				 * icb: field 1: 1 "m"
				 * icb: field 2: 8 "pelotass"
				 * icb: field 3: 3 "355"
				 * icb: field 4: 1 "0"
				 * icb: field 5: 10 "1134676594"
				 * icb: field 6: 8 "pelotass"
				 * icb: field 7: 14 "[84.10.69.233]"
				 * icb: field 8: 4 "(nr)"
				 */
				if (packet->nof == 9 && (strncmp(packet->fields[0], "wl", 2) == 0)) {
					PurpleConversation *conv;

					/* wl is response for group list query */
					if (icb->wl == WL_MODE_GROUP_LIST) {
						conv = icb_get_current_group(gc->account, icb->chat_id);
						if (!conv)
							break;

						purple_debug_info("icb", "new user=%s\n", packet->fields[2]);
						purple_conv_chat_add_user(purple_conversation_get_chat_data(conv), packet->fields[2], NULL,
							packet->fields[1][0] == 'm' ? PURPLE_CBFLAGS_OP : PURPLE_CBFLAGS_NONE, FALSE);
					/* wl is a response to get_info callback */
					} else if (strcmp(packet->fields[2], icb->wl_nick) == 0) {
						icb_show_get_info(icb, packet);
						icb->wl_nick[0] = '\0';
					}
				/* packet with Mod and Topic */
				} else if (packet->nof == 2 && (strncmp(packet->fields[0], "co", 2) == 0)
				           && ((tmp = strstr(packet->fields[1], ICB_TOPIC)) != NULL)) {
					PurpleConversation *conv;

					purple_debug_info("icb", "New topic is: %s\n", tmp + strlen(ICB_TOPIC));

					conv = icb_get_current_group(gc->account, icb->chat_id);
					if (!conv)
						break;

					purple_conv_chat_set_topic(purple_conversation_get_chat_data(conv), "(unknown)",
						tmp + strlen(ICB_TOPIC));
				/*
				 * icb: command: i
				 * icb: field 0: 2 "co"
				 * icb: field 1: 48 "help                            lists this table"
				 */
				} else if (packet->nof == 2 && (strncmp(packet->fields[0], "co", 2) == 0)
				    && (strlen(packet->fields[1]) != 1 || packet->fields[1][0] != ' ')) {
#if 0
					PurpleConversation *conv;                                                                                                                      
#endif
					serv_got_im(gc, ICB_SERVICES_NAME, packet->nof == 1 ? "" : packet->fields[1], 0, time(NULL));
#if 0
					conv = icb_get_current_group(gc->account, icb->chat_id);                                                                                     
					if (conv) {
						purple_conv_chat_write(PURPLE_CONV_CHAT(conv), "", packet->fields[1],                                                                                          
								PURPLE_MESSAGE_SYSTEM, time(NULL));                                                                                                    
					/* co's before first conv are assumed to be MOTD */
					} else {
						char *escaped;

						if (icb->motd == NULL) 
							icb->motd = g_string_new("");

					        escaped = g_markup_escape_text(packet->fields[1], -1);
						g_string_append_printf(icb->motd, "%s<br>", escaped);
						g_free(escaped);
					}
#endif
			
				}
			case ICB_CMD_PONG:
				purple_debug_info("icb", "pong msg\n");
				break;
			default:
				break;
		}
		icb_free_packet(&packet);
	}

	/* Move data left in buffer to the beginning */
	if (icb_input_fill > 0 && icb_input_pos != icb_input_buf) {
		memmove(icb_input_buf, icb_input_pos, icb_input_fill);
		*(icb_input_buf + icb_input_fill) = '\0';
	}

	icb_input_pos = icb_input_buf;

	purple_debug_misc("icb", "<- icb_input_cb()\n");
}

static void
icb_close(PurpleConnection *gc)
{
	IcbSession *icb = gc->proto_data;

	purple_debug_info("icb", "-> icb_close\n");

	if (icb == NULL) {
		purple_debug_info("icb", "<- icb_close\n");
		return;
	}

	if (gc->inpa)
		purple_input_remove(gc->inpa);

        close(icb->fd);
        g_free(icb->server);
        g_free(icb->user);
#if 0
	g_string_free(icb->motd, TRUE);
#endif
        g_free(icb);

	purple_debug_info("icb", "<- icb_close\n");
}

static int
icb_send_chat(PurpleConnection *gc, int id, const char *message, PurpleMessageFlags flags)
{
	IcbSession *icb = gc->proto_data;
	int         r, len = strlen(message);
	char       *tmp, *pos, buf[ICB_MAX_DATA_SIZE+1];

	purple_debug_info("icb", "icb_send_chat\n");
	purple_debug_info("icb", "id=%d, len=%d, msg=\"%s\"\n", id, len, message);

	tmp = purple_markup_strip_html(message);
	
	/* Split <message> into smaller chunks, as packed size is limited to
	 * ICB_MAX_DATA_SIZE bytes.
	 */
	pos = (char *) tmp;
	while (len > 0) {
		r = len < ICB_MAX_DATA_SIZE ? len : ICB_MAX_DATA_SIZE;
		memcpy(buf, pos, r);
		buf[r] = '\0';

		pos += r;
		len -= r;
	
		r = icb_send(icb, ICB_CMD_OPEN_MSG, 1, buf);
		if (r) {
			serv_got_chat_in(gc, id, purple_connection_get_display_name(gc), 0, message, time(NULL));
		}
	}
	g_free(tmp);

	purple_debug_info("icb", "<- icb_send_chat\n");

	return 0;
}

static int
icb_send_im(PurpleConnection *gc, const char *who, const char *msg, PurpleMessageFlags flags)
{
	IcbSession       *icb = gc->proto_data;
	char              buf[ICB_PACKET_SIZE], *tmp, *pos, *appendpos;
	int               r, wholen, msglen, max_msg_size;

	wholen = strlen(who);
	msglen = strlen(msg);

	purple_debug_info("icb", "icb_send_im\n");
	purple_debug_info("icb", "who=\"%s\", len=%d, msg=\"%s\"\n", who, msglen, msg);

	tmp = purple_markup_strip_html(msg);

	/* max_msg_size is smaller than ICB_MAX_DATA_SIZE as IM packet looks like this:
	 *   -gm,username message sent by user*
	 * where:
	 *   - is packet size
	 *   , is ICB_SEPARATOR
	 *   * is NUL
	 * -3 is for "m", "," and spacebar after username.
	 */
	max_msg_size = ICB_MAX_DATA_SIZE - 3 - wholen;

	/* adding common "username " to buffer */
	memcpy(buf, who, wholen);
	buf[wholen] = ' ';

	appendpos = &buf[wholen + 1];
	pos = (char *) tmp;
	while (msglen > 0) {
		r = msglen < max_msg_size ? msglen : max_msg_size;
		memcpy(appendpos, pos, r);
		*(appendpos + r) = '\0';

		pos += r;
		msglen -= r;

		r = icb_send(icb, ICB_CMD_COMMAND, 2, "m", buf);
		if (r <= 0) {
			g_free(tmp);
			return 0;
		} 
	}
	g_free(tmp);

	purple_debug_info("icb", "<- icb_send_im\n");

	return 1;
}

static void
icb_get_info(PurpleConnection *gc, const char *who)
{
	IcbSession *icb = gc->proto_data;
	int         ret;

	purple_debug_info("icb", "-> icb_get_info: %s\n", who);

	SET_WL_MODE(icb, WL_MODE_GET_INFO);

	icb->wl_nick[0] = '\0';
	strncat(icb->wl_nick, who, sizeof(icb->wl_nick) - 1);

	ret = icb_send(icb, ICB_CMD_COMMAND, 2, "w", "");
	if (ret < 0) {
		purple_connection_error(gc, _("Unable to access user profile."));
		return;
	}

	purple_debug_info("icb", "<- icb_get_info\n");
}

static void
icb_join_chat(PurpleConnection *gc, GHashTable *data)
{
	IcbSession *icb = gc->proto_data;
	char       *group;

	purple_debug_info("icb", "-> icb_join_chat\n");

	group = g_hash_table_lookup(data, "group");
	purple_debug_info("icb", "group %s\n", group);
	/*
	 * auto-reconnect calls icb_join_chat when group is not in the hash
	 * table. ignore these calls gracefully instead of segfaulting in
	 * icb_send.
         */
	if (group != NULL) {
		icb_send(icb, ICB_CMD_COMMAND, 2, "g", group);
	}

	purple_debug_info("icb", "<- icb_join_chat\n");
}

static void
icb_leave_chat(PurpleConnection *gc, int id)
{
	PurpleConversation *conv;
	IcbSession *icb = gc->proto_data;
	const char *maingroup = purple_account_get_string(gc->account, "group", ICB_DEFAULT_GROUP);

	purple_debug_info("icb", "-> icb_leave_chat\n");

	/* We cannot leave our main group */
	conv = purple_find_chat(gc, id);
	if (strcmp(conv->name, maingroup) == 0) {
		SET_WL_MODE(icb, WL_MODE_GROUP_LIST);
		icb_send(icb, ICB_CMD_COMMAND, 2, "w", ".");
		serv_got_joined_chat(gc, icb->chat_id, conv->name);
	} else {
		/* You cannot leave group without joining another */
		icb_send(icb, ICB_CMD_COMMAND, 2, "g",
				purple_account_get_string(gc->account, "group", ICB_DEFAULT_GROUP));
	}

	purple_debug_info("icb", "<- icb_leave_chat\n");
}

static const char *
icb_list_icon(PurpleAccount *a, PurpleBuddy *b)
{
	return "icb";
}

static GList *
icb_chat_info(PurpleConnection *gc)
{
	GList                   *m = NULL;
	struct proto_chat_entry *pce;

	purple_debug_misc("icb", "-> icb_chat_info\n");

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Group:");
	pce->identifier = "group";
	m = g_list_append(m, pce);

	purple_debug_misc("icb", "<- icb_chat_info\n");

	return m;
}

static PurpleCmdRet
icb_purple_send_cmd(PurpleConversation *conv, char *command)
{
	int         r;
	IcbSession *icb;

	icb = purple_conversation_get_gc(conv)->proto_data;

	r = icb_send(icb, ICB_CMD_COMMAND, 2, "m", command);
	if (r <= 0)
		return PURPLE_CMD_RET_FAILED;

        return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
icb_purple_cmd_topic(PurpleConversation *conv,
	const char *cmd, char **args, char **error, void *data)
{
	int  r;
	char buf[ICB_MAX_DATA_SIZE+1];

	r = snprintf(buf, sizeof(buf), "server topic %s", args[0]);
	if (r <= 0)
		return PURPLE_CMD_RET_FAILED;

	return icb_purple_send_cmd(conv, buf);
}

static PurpleCmdRet                                                                                                                                                                   
icb_purple_cmd_brick(PurpleConversation *conv,                                                                                                                                          
	const char *cmd, char **args, char **error, void *data)                                                                                                                      
{                                                                                                                                                                                   
	int r;                                                                                                                                                                      
	char buf[ICB_MAX_DATA_SIZE+1];                                                                                                                                               

	r = snprintf(buf, sizeof(buf), "server brick %s", args[0]);                                                                                                                  
	if (r <= 0)                                                                                                                                                                  
		return PURPLE_CMD_RET_FAILED;                                                                                                                                          

	return icb_purple_send_cmd(conv, buf);                                                                                                                                         
}                                                                                                                                                                                   

static PurpleCmdRet
icb_purple_cmd_m(PurpleConversation *conv,
	const char *cmd, char **args, char **error, void *data)
{
	int  r;
	char buf[ICB_MAX_DATA_SIZE+1];

	r = snprintf(buf, sizeof(buf), "%s %s", args[0], args[1]);
	if (r <= 0)
		return PURPLE_CMD_RET_FAILED;

	return icb_purple_send_cmd(conv, buf);
}

static PurpleCmdRet
icb_purple_cmd_pass(PurpleConversation *conv,
	const char *cmd, char **args, char **error, void *data)
{
	int  r;
	char buf[ICB_MAX_DATA_SIZE+1];

	r = snprintf(buf, sizeof(buf), "server pass %s", args[0]);
	if (r <= 0)
		return PURPLE_CMD_RET_FAILED;

	return icb_purple_send_cmd(conv, buf);
}

static PurpleCmdRet
icb_purple_cmd_nick(PurpleConversation *conv,
	const char *cmd, char **args, char **error, void *data)
{
	int  r;
	char buf[ICB_MAX_DATA_SIZE+1];

	r = snprintf(buf, sizeof(buf), "server name %s", args[0]);
	if (r <= 0)
		return PURPLE_CMD_RET_FAILED;

	return icb_purple_send_cmd(conv, buf);
}

static char *
icb_status_text(PurpleBuddy *b)
{
        PurpleStatus *status;
        const char *msg;
        char *text = NULL;
        char *tmp;

        status = purple_presence_get_active_status(purple_buddy_get_presence(b));
        msg = purple_status_get_attr_string(status, "message");
        if (msg != NULL) {
                tmp = purple_markup_strip_html(msg);
                text = g_markup_escape_text(tmp, -1);
                g_free(tmp);
        }

	purple_debug_info("icb", "icb_status_text: %s tb=%p ret=%s\n", b->name, b->proto_data, text);

	return text;
}

static const char *
icb_list_emblems(PurpleBuddy *b)
{
	return NULL;
}

static PurpleCmdRet
icb_purple_cmd_kick(PurpleConversation *conv,
	const char *cmd, char **args, char **error, void *data)
{
	int  r;
	char buf[ICB_MAX_DATA_SIZE+1];

	r = snprintf(buf, sizeof(buf), "server boot %s", args[0]);
	if (r <= 0)
		return PURPLE_CMD_RET_FAILED;

	return icb_purple_send_cmd(conv, buf);
}

#if 0
static void
icb_view_motd(PurplePluginAction *action)
{
        PurpleConnection *gc = (PurpleConnection *) action->context;
        IcbSession *icb;
        char *title;

        icb = gc->proto_data;
        if (icb->motd == NULL) {
		purple_notify_error(gc, _("Error displaying MOTD"), _("No MOTD available"),
			_("There is no MOTD associated with this connection."));
                return;
        }

        title = g_strdup_printf(_("MOTD for %s:%d"), icb->server, icb->port);
        purple_notify_formatted(gc, title, title, NULL, icb->motd->str, NULL, NULL);
}
#endif

#if 0
static GList *
icb_actions(PurplePlugin *plugin, gpointer context)
{
	GList *list = NULL;
	PurplePluginAction *act = NULL; 

	act = purple_plugin_action_new(_("View MOTD"), icb_view_motd);
	list = g_list_append(list, act);

	return list;
}
#endif

static void
icb_set_chat_topic(PurpleConnection *gc, int id, const char *topic)
{
	PurpleConversation *conv;
	char              buf[ICB_MAX_DATA_SIZE+1];
	int               r;

	conv = icb_get_current_group(gc->account, id);
	if (conv == NULL) 
		return;

	r = snprintf(buf, sizeof(buf), "server topic %s", topic);
	if (r <= 0)
		return;

	icb_purple_send_cmd(conv, buf);

	return;
}

GHashTable *
icb_chat_info_defaults(PurpleConnection *gc, const char *chat_name)
{
	GHashTable *defaults;

	purple_debug_misc("icb", "-> icb_chat_info_defaults\n");

        defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	if (chat_name)
		purple_debug_misc("icb", "chat_name='%s' (%p)\n",
		    chat_name, chat_name);
	else
		purple_debug_misc("icb", "chat_name is NULL\n");

#if 0
        if (chat_name != NULL)
                g_hash_table_insert(defaults, "room", g_strdup(chat_name));
#endif

	purple_debug_misc("icb", "<- icb_chat_info_defaults\n");

        return defaults;
}

static void
icb_keepalive(PurpleConnection *gc)
{
	IcbSession     *icb = gc->proto_data;

	purple_debug_misc("icb", "-> icb_keepalive\n");

	if ((time(NULL) - icb->sr_time) >= KEEPALIVE_TIMEOUT)
		icb_send(icb, ICB_CMD_PONG, 0);

	purple_debug_misc("icb", "<- icb_keepalive\n");
}

static PurplePlugin *icb_plugin = NULL;

static PurplePluginProtocolInfo prpl_info =
{
	OPT_PROTO_CHAT_TOPIC | OPT_PROTO_PASSWORD_OPTIONAL,
	NULL,			/* user_splits */
	NULL,			/* protocol_options */
	NO_BUDDY_ICONS,		/* icon_spec */
	icb_list_icon,		/* list_icon */
	icb_list_emblems,	/* list_emblems */
	icb_status_text,	/* status_text */
	NULL,			/* tooltip_text */
	icb_status_types,	/* status_types */
	NULL,			/* blist_node_menu */
	icb_chat_info,		/* chat_info */
	icb_chat_info_defaults,	/* chat_info_defaults */
	icb_login,		/* login */
	icb_close,		/* close */
	icb_send_im,		/* send_im */
	NULL,			/* set_info */
	NULL,			/* send_typing */
	icb_get_info,		/* get_info */
	NULL,			/* set_away */
	NULL,			/* set_idle */
	NULL,			/* change_passwd */
	NULL,			/* add_buddy */
	NULL,			/* add_buddies */
	NULL,			/* remove_buddy */
	NULL,			/* remove_buddies */
	NULL,			/* add_permit */
	NULL,			/* add_deny */
	NULL,			/* rem_permit */
	NULL,			/* rem_deny */
	NULL,			/* set_permit_deny */
	icb_join_chat,		/* join_chat */
	NULL,			/* reject_chat */
	NULL,			/* get_chat_name */
	NULL,			/* chat_invite */
	icb_leave_chat,		/* chat_leave */
	NULL,			/* chat_whisper */
	icb_send_chat,		/* chat_send */
	icb_keepalive,		/* keepalive */
	NULL,			/* register_user */
	NULL,			/* get_cb_info */
	NULL,			/* get_cb_away */
	NULL,			/* alias_buddy */
	NULL,			/* group_buddy */
	NULL,			/* rename_group */
	NULL,			/* buddy_free */
	NULL,			/* convo_closed */
	NULL,			/* normalize */
	NULL,			/* set_buddy_icon */
	NULL,			/* remove_group */
	NULL,			/* get_cb_real_name */
	icb_set_chat_topic,	/* set_chat_topic */
	NULL,			/* find_blist_chat */
	NULL,			/* roomlist_get_list */
	NULL,			/* roomlist_cancel */
	NULL,			/* roomlist_expand_category */
	NULL,			/* can_receive_file */
	NULL			/* send_file */
};

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                        /**< type           */
	NULL,                                        /**< ui_requirement */
	0,                                           /**< flags          */
	NULL,                                        /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                       /**< priority       */

	"prpl-icb",		                     /**< id             */
	"ICB",                                       /**< name           */
	ICB_VERSION,                                 /**< version        */
	N_("ICB Protocol Plugin"),                   /**  summary        */
	N_("Internet Citizen's Band Protocol Plugin"), /**  description    */
	"Aleksander Piotrowski <aleksander.piotrowski@nic.com.pl>", /**< author         */
	"http://nic.com.pl/~alek/gaim-icb/",          /**< homepage       */

	NULL,                                        /**< load           */
	NULL,                                        /**< unload         */
	NULL,                                        /**< destroy        */

	NULL,                                        /**< ui_info        */
	&prpl_info,                                  /**< extra_info     */
	NULL,
	NULL // icb_actions
};

void
init_plugin(PurplePlugin *plugin)
{
	PurpleAccountUserSplit *split;
	PurpleAccountOption *option;

	split = purple_account_user_split_new(_("Server"), ICB_DEFAULT_SERVER, '@');
	prpl_info.user_splits = g_list_append(prpl_info.user_splits, split);

	option = purple_account_option_int_new(_("Port"), "port", ICB_DEFAULT_PORT);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Default group"), "group", ICB_DEFAULT_GROUP);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Login id"), "login_id", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	icb_plugin = plugin;

	purple_cmd_register("nick","w", PURPLE_CMD_P_PRPL,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
		"prpl-icb",
		icb_purple_cmd_nick,
		_("nick &lt;new nickname&gt;: Changes current nickname to &quot;new nickname&quot;"),
		NULL);
	purple_cmd_register("name","w", PURPLE_CMD_P_PRPL,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
		"prpl-icb",
		icb_purple_cmd_nick,
		_("name &lt;new nickname&gt;: Changes current nickname to &quot;new nickname&quot;"),
		NULL);
	purple_cmd_register("kick","w", PURPLE_CMD_P_PRPL,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
		"prpl-icb",
		icb_purple_cmd_kick,
		_("kick &lt;nickname&gt;: If you are group moderator, removes &quot;nickname&quot; from group"),
		NULL);
	purple_cmd_register("boot","w", PURPLE_CMD_P_PRPL,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
		"prpl-icb",
		icb_purple_cmd_kick,
		_("boot &lt;nickname&gt;: If you are group moderator, removes &quot;nickname&quot; from group"),
		NULL);
	purple_cmd_register("brick","w", PURPLE_CMD_P_PRPL,                                                                                                                              
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,                                                                                                     
		"prpl-icb",                                                                                                                                                          
		icb_purple_cmd_brick,                                                                                                                                                  
		_("brick &lt;nickname&gt;: Throw a brick at &quot;nickname&quot;"),                                                                                                  
		NULL);
	purple_cmd_register("m","ws", PURPLE_CMD_P_PRPL,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
		"prpl-icb",
		icb_purple_cmd_m,
		_("m &lt;nick&gt; &lt;message&gt;: Send &quot;message&quot; to &quot;nickname&quot;"),
		NULL);
	purple_cmd_register("topic","s", PURPLE_CMD_P_PRPL,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
		"prpl-icb",
		icb_purple_cmd_topic,
		_("topic &lt;new topic&gt;: Changes topic for current group"),
		NULL);
	purple_cmd_register("pass","w", PURPLE_CMD_P_PRPL,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
		"prpl-icb",
		icb_purple_cmd_pass,
		_("pass &lt;nickname&gt; Passes moderator privileges to &lt;nickname&gt;"),
		NULL);
	purple_cmd_register("op","w", PURPLE_CMD_P_PRPL,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
		"prpl-icb",
		icb_purple_cmd_pass,
		_("op &lt;nickname&gt; Passes moderator privileges to &lt;nickname&gt;"),
		NULL);
}

PURPLE_INIT_PLUGIN(icb, init_plugin, info);

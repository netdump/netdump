/**
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */

#include "display.h"
#include "msgcomm.h"


/**
 * @brief The global flag of display tui, used to exit tui
 * @note
 * 	display_G_flag = 1; 
 * 	indicates an exception occurs and the system needs to exit
 */
unsigned char display_G_flag = 0;

/**
 * @brief 
 * 	Define a global variable to store the resources required by TUI
 * @note
 *  G_display.wins[0]: Netdump ASCII world
 *  G_display.wins[1]: Information of author
 *  G_display.wins[2]: Command input box
 *  G_display.wins[3]: Brief information display box
 *  G_display.wins[4]: Detailed information display box
 *  G_display.wins[5]: Original hexadecimal information display box
 *  G_display.panels[0]: The panel associated with G_display.wins[0]
 *  G_display.panels[1]: The panel associated with G_display.wins[1]
 *  G_display.panels[2]: The panel associated with G_display.wins[2]
 *  G_display.panels[3]: The panel associated with G_display.wins[3]
 *  G_display.panels[4]: The panel associated with G_display.wins[4]
 *  G_display.panels[5]: The panel associated with G_display.wins[5]
 */
display_t G_display = {
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}
};


/**
 * @brief 
 * 	Format the title bar title
 * @param win: 
 * 	The window that is designated to format the input title
 * @param starty: 
 * 	The starting position of the title bar relative to the window's Y coordinate
 * @param startx: 
 * 	The starting position of the title bar relative to the window's X coordinate
 * @param width: 
 * 	Width of the title bar
 * @param string: 
 * 	Contents of the title bar
 * @param color: 
 * 	Color attribute of the title bar content
 */
int display_format_set_window_title(WINDOW *win, int starty, int startx, int width, char *string, chtype color) {

	TC("Called { %s (%p, %d, %d, %d, %s, %u)", __func__, win, starty, startx, width, string, color);

    int length, x, y;
	float temp;

	if(win == NULL)
		win = stdscr;

	getyx(win, y, x);

	if(startx != 0)
		x = startx;
	if(starty != 0)
		y = starty;
	if(width == 0)
		width = 80;

	length = strlen(string);
	temp = (width - length) / 2;
	x = startx + (int)temp;
	wattron(win, color);
	mvwprintw(win, y, x, "%s", string);
	wattroff(win, color);
	refresh();

	RInt(0);
}


/**
 * @brief 
 * 	TUI shows process exit resource destruction
 */
void display_exit_resource_destruction () {

	TC("called { %s", __func__);

	display_exit_TUI_showcase();

	RVoid();
}


/**
 * @brief 
 * 	The display process communicates with the capture process
 * @param command
 * 	Pointer to the message content
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int display_cmd_to_capture (const char * command) {

	TC("Called { %s()", __func__);

	if (unlikely((!command))) {
		TE("param error; command: %s", command);
		RInt(ND_ERR);
	}

	if ( unlikely(
		((msgcomm_message_send(MSGCOMM_DIR_0TO1, MSGCOMM_CMD, command, strlen(command))) == ND_ERR)
	))
	{
		TE("msgcomm message send failed");
		RInt(ND_ERR);
	}

	RInt(ND_OK);
}


/**
 * @brief 
 * 	Receive messages from the capture process
 * @param message
 * 	Storing Messages
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int display_reply_from_capture (message_t * message) {

	TC("Called { %s(%p)", __func__, message);

	if (unlikely((!message))) {
        TE("param error; message: %p", message);
        RInt(ND_ERR);
    }

    if (unlikely((msgcomm_message_recv(MSGCOMM_DIR_1TO0, message)) == ND_ERR)) {
        TE("msgcomm message recv failed");
        RInt(ND_ERR);
    }

	RInt(ND_OK);
}


/**
 * @brief 
 * 	Error message display
 * @param prefix
 * 	message prefix
 * @param msg
 * 	message
 * @param win
 * 	message display window
 * @param panel 
 * 	message window control panel
 * @param color
 * 	color pair
 */
static void display_message_display (const char * prefix, const char * msg, WINDOW * win, PANEL * panel, int color) {

	TC("Called { %s(%s, %s, %p, %p, %d)", __func__, prefix, msg, win, panel, color);

	char * space = malloc(1024 * 1024);
	if (!space) {
		TE("malloc(1024 * 1024) failed");
		RVoid();
	}

	show_panel(panel); 
	update_panels();
	doupdate();
	wmove(win, 2, 3);
	wattrset(win, A_NORMAL);
	wclrtoeol(win);
	wattrset(win, A_BOLD);
	wattron(win, COLOR_PAIR((color)));
	snprintf(space, 1024 * 1024, "%s\n\t%s\n", prefix, msg);
	waddstr(win, space);
	wattroff(win, COLOR_PAIR((color)));
	wattron(win, COLOR_PAIR((color)));
	box(win, 0, 0);
	wattroff(win, COLOR_PAIR((color)));
	refresh();
	wrefresh(win);
	getchar();
	wclear(win);
	hide_panel(panel);
	update_panels();
	doupdate();

	free(space);
	RVoid();
}


/**
 * @brief
 * 	Display the processing logic interface of the first interface of the process
 * @param command
 * 	Commands entered via the tui interface
 * @param errwin
 * 	Error message display window
 * @param errpanel
 * 	Error message window control panel
 * @param infowin
 * 	info message display window
 * @param infopanel
 * 	info message window control panel
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int display_first_tui_handle_logic(const char *command, WINDOW *errwin, PANEL *errpanel, WINDOW *infowin, PANEL *infopanel)
{

	TC("Called { %s(%s, %p, %p)", __func__, command, errwin, errpanel);

	if (unlikely((!command) || (!errwin) || (!errpanel) || (!infowin) || (!infopanel)))
	{
		TE("param error; command: %s, errwin: %p, errpanel: %p, infowin: %p, infopanel: %p", command, errwin, errpanel, infowin, infopanel);
		RInt(ND_ERR);
	}

	int count = 0, i = 0, len = strlen(command);
	for (i = 0; i < len; i++)
	{
		if (command[i] == '-')
		{
			count++;
		}
	}
	if (!count)
	{
		display_message_display("ERROR MSG:", "Missing '-' character", errwin, errpanel, 4);
		RInt(ND_ERR);
	}

	if (unlikely(((display_cmd_to_capture(command))))) {
		TE("display cmd to capture failed");
		RInt(ND_ERR);
	}

	char space[1024] = {0};
	message_t * message = (message_t *)(space);
	if (unlikely(((display_reply_from_capture(message)) == ND_ERR))) {
		TE("display reply from capture failed");
		RInt(ND_ERR);
	}

	TI("     ");
	TI("message->dir: %u", message->dir);
	TI("message->msgtype: %u", message->msgtype);
	TI("message->length: %u", message->length);
	TI("message->msg: %s", message->msg);

	if (message->msgtype == MSGCOMM_ERR) {
		TI("%s", message->msg);
		display_message_display("ERROR MSG:", (const char *)(message->msg), errwin, errpanel, 4);
		RInt(ND_ERR);
	}
	else if (message->msgtype == MSGCOMM_HLP)
	{
		display_message_display("HELP MSG:", (const char *)(message->msg), infowin, infopanel, 5);
		RInt(ND_ERR);
	}
	else if (message->msgtype == MSGCOMM_FAD)
	{
		display_message_display("ALLDEVICE MSG:", (const char *)(message->msg), infowin, infopanel, 5);
		RInt(ND_ERR);
	}
	else if (message->msgtype == MSGCOMM_DLT)
	{
		display_message_display("DATA-LINK-TYPE MSG:", (const char *)(message->msg), infowin, infopanel, 5);
		RInt(ND_ERR);
	}
	else if (message->msgtype == MSGCOMM_SUC)
	{
		
	}

	RInt(ND_OK);
}
